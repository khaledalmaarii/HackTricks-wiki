# Weaponizing Distroless

{% hnnt styte=" acceas" %}
GCP हैकिंग प्रैक्टिस: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
सीखें और GCP में अभ्यास करें<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*चेक करें [**subsrippangithub.cm/sorsarlosp!**
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) या [**telegram group**](https://t.me/peass) या **follow** करें हमें **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## What is Distroless

एक distroless कंटेनर एक प्रकार का कंटेनर है जो **एक विशिष्ट एप्लिकेशन को चलाने के लिए आवश्यक निर्भरताओं** को ही **शामिल करता है**, बिना किसी अतिरिक्त सॉफ़्टवेयर या उपकरणों के जो आवश्यक नहीं हैं। ये कंटेनर **हल्के** और **सुरक्षित** होने के लिए डिज़ाइन किए गए हैं, और वे **हमले की सतह को कम करने** का लक्ष्य रखते हैं, अनावश्यक घटकों को हटा कर।

Distroless कंटेनर अक्सर **उत्पादन वातावरण में उपयोग किए जाते हैं जहां सुरक्षा और विश्वसनीयता सर्वोपरि हैं**।

कुछ **उदाहरण** **distroless कंटेनरों** के हैं:

* **Google** द्वारा प्रदान किया गया: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* **Chainguard** द्वारा प्रदान किया गया: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

एक distroless कंटेनर को हथियार बनाने का लक्ष्य यह है कि **मनमाने बाइनरी और पेलोड को निष्पादित किया जा सके, भले ही distroless द्वारा लगाए गए सीमाओं** (सिस्टम में सामान्य बाइनरी की कमी) और कंटेनरों में आमतौर पर पाए जाने वाले सुरक्षा उपायों जैसे **पढ़ने के लिए केवल** या **निष्पादित न करें** `/dev/shm` में।

### Through memory

2023 के किसी बिंदु पर आ रहा है...

### Via Existing binaries

#### openssl

****[**इस पोस्ट में,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) यह बताया गया है कि बाइनरी **`openssl`** अक्सर इन कंटेनरों में पाई जाती है, संभवतः क्योंकि यह **जरूरी** है उस सॉफ़्टवेयर के लिए जो कंटेनर के अंदर चलने वाला है।
{% hnt stye="acceas" %}
AWS हैकिंग प्रैक्टिस: <img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
सीखें और GCP में अभ्यास करें<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*चेक करें [**subsrippangithub.cm/sorsarlosp!**
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) या [**telegram group**](https://t.me/peass) या **follow** करें हमें **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
