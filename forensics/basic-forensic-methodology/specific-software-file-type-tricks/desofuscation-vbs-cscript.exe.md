<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**Telegram群组**](https://t.me/peass) 或者 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


一些对于调试/反混淆恶意VBS文件有用的东西：

## echo
```bash
Wscript.Echo "Like this?"
```
## 评论

---

### Desofuscation VBS CScript.exe

---

#### Description

This technique is used to deobfuscate VBS (Visual Basic Script) code that has been obfuscated using the CScript.exe utility. CScript.exe is a command-line tool that is used to execute VBScript code. By analyzing the obfuscated code and understanding the obfuscation techniques used, it is possible to reverse the obfuscation and obtain the original VBS code.

#### Steps

1. Identify the obfuscated VBS code that has been obfuscated using CScript.exe.

2. Analyze the obfuscated code to understand the obfuscation techniques used. This may include techniques such as string concatenation, character substitution, and encoding.

3. Use a combination of manual analysis and automated tools to reverse the obfuscation and obtain the original VBS code.

4. Once the original VBS code has been obtained, analyze it for any malicious or suspicious behavior.

#### Tools

- Text editor: A text editor can be used to manually analyze the obfuscated code and make changes to reverse the obfuscation.

- VBScript deobfuscation tools: There are several tools available that can automatically deobfuscate VBS code obfuscated using CScript.exe. These tools can help speed up the process of reversing the obfuscation.

#### Example

The following is an example of obfuscated VBS code that has been obfuscated using CScript.exe:

```vbscript
Dim a, b, c
a = "Hello"
b = "World"
c = a & b
WScript.Echo c
```

By analyzing the obfuscated code, it can be determined that the obfuscation technique used is string concatenation. The original VBS code can be obtained by reversing the string concatenation:

```vbscript
WScript.Echo "Hello" & "World"
```

#### Mitigation

To protect against this technique, it is important to use strong obfuscation techniques when obfuscating VBS code. Additionally, regularly scanning and analyzing VBS code for any malicious or suspicious behavior can help detect and mitigate any potential threats.
```text
' this is a comment
```
## 测试
```text
cscript.exe file.vbs
```
## 写入文件数据

To write data to a file in Python, you can use the `write()` method of the file object. This method allows you to write a string of data to the file.

```python
# Open the file in write mode
file = open("filename.txt", "w")

# Write data to the file
file.write("Hello, world!")

# Close the file
file.close()
```

In the above example, we open the file "filename.txt" in write mode using the `open()` function. Then, we use the `write()` method to write the string "Hello, world!" to the file. Finally, we close the file using the `close()` method.

Remember to handle exceptions and errors that may occur while writing to a file.
```aspnet
Function writeBinary(strBinary, strPath)

Dim oFSO: Set oFSO = CreateObject("Scripting.FileSystemObject")

' below lines purpose: checks that write access is possible!
Dim oTxtStream

On Error Resume Next
Set oTxtStream = oFSO.createTextFile(strPath)

If Err.number <> 0 Then MsgBox(Err.message) : Exit Function
On Error GoTo 0

Set oTxtStream = Nothing
' end check of write access

With oFSO.createTextFile(strPath)
.Write(strBinary)
.Close
End With

End Function
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**Telegram群组**](https://t.me/peass)，或者在**Twitter**上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
