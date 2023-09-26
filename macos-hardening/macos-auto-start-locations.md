# macOS自动启动位置

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

以下是系统中可能导致二进制文件**在没有用户交互的情况下**执行的位置。

### Launchd

**`launchd`**是在启动时由OS X内核执行的**第一个进程**，也是在关机时最后一个完成的进程。它应该始终具有**PID 1**。此进程将**读取并执行**在以下位置指定的**ASEP** **plists**中的配置：

* `/Library/LaunchAgents`：由管理员安装的每个用户代理
* `/Library/LaunchDaemons`：由管理员安装的系统级守护程序
* `/System/Library/LaunchAgents`：由Apple提供的每个用户代理
* `/System/Library/LaunchDaemons`：由Apple提供的系统级守护程序

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
<string>/Users/username/malware</string>
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
有些情况下，需要在用户登录之前执行代理程序，这些称为“PreLoginAgents”。例如，这对于在登录时提供辅助技术非常有用。它们也可以在`/Library/LaunchAgents`中找到（参见[此处](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)的示例）。

\{% hint style="info" %\}新的守护程序或代理程序配置文件将在下次重启后加载，或使用`launchctl load <target.plist>`命令加载。也可以使用`launchctl -F <file>`加载没有扩展名的.plist文件（但这些plist文件不会在重启后自动加载）。
也可以使用`launchctl unload <target.plist>`卸载（指向它的进程将被终止）。

为了确保没有任何东西（如覆盖）阻止代理程序或守护程序运行，请运行：`sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist` \{% endhint %\}

列出当前用户加载的所有代理程序和守护程序：
```bash
launchctl list
```
### Cron

使用以下命令列出**当前用户**的cron作业：
```bash
crontab -l
```
您还可以在**`/usr/lib/cron/tabs/`**和**`/var/at/tabs/`**（需要root权限）中查看用户的所有cron作业。

在MacOS中，可以找到以**特定频率**执行脚本的几个文件夹：
```bash
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
在这里，你可以找到常规的**cron**任务，**at**任务（不常用）和周期性任务（主要用于清理临时文件）。例如，可以使用`periodic daily`来执行每日周期性任务。

周期性脚本（**`/etc/periodic`**）是由在`/System/Library/LaunchDaemons/com.apple.periodic*`中配置的**启动守护程序**执行的。请注意，如果将脚本存储在`/etc/periodic/`中以提升权限，它将作为文件的所有者**执行**。
```bash
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist
```
### kext

为了将KEXT安装为启动项，它需要被安装在以下位置之一：

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

### **登录项**

在“系统偏好设置” -> “用户与群组” -> **登录项**中，您可以找到**用户登录时要执行的项目**。\
可以通过命令行列出、添加和删除它们：
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
这些项目存储在文件/Users/\<username>/Library/Application Support/com.apple.backgroundtaskmanagementagent中。

### 将ZIP文件作为登录项

如果将ZIP文件存储为登录项，**`Archive Utility`**将打开它，如果ZIP文件例如存储在**`~/Library`**中，并包含文件夹**`LaunchAgents/file.plist`**，其中包含后门，该文件夹将被创建（默认情况下不存在），并且plist将被添加，因此下次用户再次登录时，将执行plist中指定的**后门**。

另一种选择是在用户主目录中创建文件**`.bash_profile`**和**`.zshenv`**，因此如果LaunchAgents文件夹已经存在，此技术仍然有效。

### At

“At tasks”用于**在特定时间安排任务**。\
这些任务与cron不同，它们是**一次性任务**，在执行后会被删除。但是，它们将**在系统重启后保留**，因此不能将其排除为潜在威胁。

默认情况下，它们是**禁用的**，但**root用户**可以通过以下方式**启用它们**：
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
这将在13:37创建一个文件：
```bash
echo hello > /tmp/hello | at 1337
```
如果未启用 AT 任务，则创建的任务将不会被执行。

### 登录/注销钩子

它们已被弃用，但可以用于在用户登录时执行命令。
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
```
这个设置存储在 `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` 文件中。
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
要删除它：
```bash
defaults delete com.apple.loginwindow LoginHook
```
在前面的示例中，我们创建并删除了一个**LoginHook**，也可以创建一个**LogoutHook**。

root用户的Hook存储在`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`中。

### 应用程序首选项

在**`~/Library/Preferences`**中存储了用户在应用程序中的首选项。其中一些首选项可以保存配置以**执行其他应用程序/脚本**。

例如，终端可以在启动时执行一个命令：

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

这个配置在文件**`~/Library/Preferences/com.apple.Terminal.plist`**中反映出来，如下所示：
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
所以，如果系统中终端的偏好设置的plist文件被覆盖，那么可以使用**`open`**功能来**打开终端并执行该命令**。

### Emond

苹果引入了一个名为**emond**的日志记录机制。看起来它从未完全开发，并且苹果可能已经**放弃**了它以使用其他机制，但它仍然**可用**。

这个鲜为人知的服务对于Mac管理员来说**可能没有太多用处**，但对于威胁行为者来说，一个非常好的理由是将其用作**持久性机制，大多数macOS管理员可能不会知道**去寻找。检测emond的恶意使用不应该很困难，因为该服务的系统LaunchDaemon只会在一个地方寻找要运行的脚本：
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
