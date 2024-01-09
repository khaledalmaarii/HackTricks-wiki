<details>

<summary><strong>AWS हैकिंग सीखें शून्य से नायक तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs संग्रह**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** को अपनी हैकिंग ट्रिक्स साझा करके PRs सबमिट करें [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


# GUI एप्लिकेशन के अंदर संभावित क्रियाओं की जांच करें

**Common Dialogs** वे विकल्प होते हैं जैसे **फाइल सेव करना**, **फाइल खोलना**, फॉन्ट चुनना, रंग चुनना... अधिकांश आपको **पूर्ण Explorer कार्यक्षमता प्रदान करेंगे**. इसका मतलब है कि यदि आप इन विकल्पों तक पहुंच सकते हैं तो आप Explorer कार्यक्षमताओं तक पहुंच सकेंगे:

* Close/Close as
* Open/Open with
* Print
* Export/Import
* Search
* Scan

आपको जांचना चाहिए कि क्या आप:

* फाइलों को संशोधित कर सकते हैं या नई फाइलें बना सकते हैं
* सिम्बोलिक लिंक्स बना सकते हैं
* प्रतिबंधित क्षेत्रों तक पहुंच सकते हैं
* अन्य एप्स चला सकते हैं

## Command Execution

शायद **_**Open with**_** विकल्प का उपयोग करके** आप किसी प्रकार का शेल खोल/चला सकते हैं।

### Windows

उदाहरण के लिए _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ और अधिक बाइनरीज जो कमांड्स चलाने के लिए (और अप्रत्याशित क्रियाएं करने के लिए) उपयोग की जा सकती हैं, यहां देखें: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ और अधिक यहां: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## पथ प्रतिबंधों को बायपास करना

* **Environment variables**: बहुत सारे environment variables होते हैं जो किसी पथ की ओर इशारा करते हैं
* **अन्य प्रोटोकॉल**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **सिम्बोलिक लिंक्स**
* **Shortcuts**: CTRL+N (नया सत्र खोलें), CTRL+R (कमांड्स चलाएं), CTRL+SHIFT+ESC (टास्क मैनेजर),  Windows+E (एक्सप्लोरर खोलें), CTRL-B, CTRL-I (पसंदीदा), CTRL-H (इतिहास), CTRL-L, CTRL-O (फाइल/ओपन डायलॉग), CTRL-P (प्रिंट डायलॉग), CTRL-S (सेव ऐज)
* छिपी हुई प्रशासनिक मेनू: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC paths**: साझा फोल्डरों से जुड़ने के लिए पथ। आपको स्थानीय मशीन के C$ से जुड़ने का प्रयास करना चाहिए ("\\\127.0.0.1\c$\Windows\System32")
* **और अधिक UNC पथ:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

## अपनी बाइनरीज डाउनलोड करें

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## ब्राउज़र से फाइलसिस्टम तक पहुंच

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## ShortCuts

* Sticky Keys – SHIFT को 5 बार दबाएं
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – NUMLOCK को 5 सेकंड के लिए दबाए रखें
* Filter Keys – दाएं SHIFT को 12 सेकंड के लिए दबाए रखें
* WINDOWS+F1 – Windows खोज
* WINDOWS+D – डेस्कटॉप दिखाएं
* WINDOWS+E – Windows Explorer लॉन्च करें
* WINDOWS+R – रन
* WINDOWS+U – Ease of Access Centre
* WINDOWS+F – खोज
* SHIFT+F10 – संदर्भ मेनू
* CTRL+SHIFT+ESC – टास्क मैनेजर
* CTRL+ALT+DEL – नए Windows संस्करणों पर स्प्लैश स्क्रीन
* F1 – मदद F3 – खोज
* F6 – पता बार
* F11 – Internet Explorer के भीतर पूर्ण स्क्रीन टॉगल करें
* CTRL+H – Internet Explorer इतिहास
* CTRL+T – Internet Explorer – नया टैब
* CTRL+N – Internet Explorer – नया पृष्ठ
* CTRL+O – फाइल खोलें
* CTRL+S – सेव CTRL+N – नया RDP / Citrix

## Swipes

* बाएं किनारे से दाएं की ओर स्वाइप करें ताकि सभी खुली Windows दिखाई दें, KIOSK ऐप को कम करें और सीधे पूरे OS तक पहुंचें;
* दाएं किनारे से बाएं की ओर स्वाइप करें ताकि एक्शन सेंटर खुले, KIOSK ऐप को कम करें और सीधे पूरे OS तक पहुंचें;
* पूर्ण स्क्रीन मोड में खुले ऐप के लिए शीर्ष किनारे से नीचे स्वाइप करें ताकि शीर्षक पट्टी दिखाई दे;
* पूर्ण स्क्रीन ऐप में नीचे से ऊपर स्वाइप करें ताकि टास्कबार दिखाई दे।

## Internet Explorer Tricks

### 'Image Toolbar'

यह एक टूलबार है जो छवि पर क्लिक करने पर ऊपर-बाएं में दिखाई देता है। आप सेव, प्रिंट, Mailto, Explorer में "My Pictures" खोल सकेंगे। Kiosk को Internet Explorer का उपयोग करना चाहिए।

### Shell Protocol

Explorer दृश्य प्राप्त करने के लिए इन URLs को टाइप करें:

* `shell:Administrative Tools`
* `shell:DocumentsLibrary`
* `shell:Libraries`
* `shell:UserProfiles`
* `shell:Personal`
* `shell:SearchHomeFolder`
* `shell:NetworkPlacesFolder`
* `shell:SendTo`
* `shell:UserProfiles`
* `shell:Common Administrative Tools`
* `shell:MyComputerFolder`
* `shell:InternetFolder`
* `Shell:Profile`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:ControlPanelFolder`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> कंट्रोल पैनल
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> मेरा कंप्यूटर
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> मेरे नेटवर्क स्थान
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

# ब्राउज़र्स ट्रिक्स

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

JavaScript का उपयोग करके एक सामान्य डायलॉग बनाएं और फाइल एक्सप्लोरर तक पहुंचें: `document.write('<input/type=file>')`
स्रोत: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gestures and bottoms

### चार (या पांच) उंगलियों से स्वाइप करें / होम बटन को डबल-टैप करें

मल्टीटास्क दृश्य देखने और ऐप बदलने के लिए

### चार या पांच उंगलियों से एक तरफ या दूसरी तरफ स
