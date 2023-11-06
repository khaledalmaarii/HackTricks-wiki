# FISSURE - आरएफ फ्रेमवर्क

**फ्रीक्वेंसी इंडिपेंडेंट एसडीआर-आधारित सिग्नल समझ और रिवर्स इंजीनियरिंग**

FISSURE एक ओपन-सोर्स आरएफ और रिवर्स इंजीनियरिंग फ्रेमवर्क है जो सिग्नल का पता लगाने और वर्गीकरण, प्रोटोकॉल खोज, हमले का क्रियान्वयन, आईक्यू मेंफिपुलेशन, सुरक्षा विश्लेषण, स्वचालन और एआई/एमएल के लिए हुक्स के साथ डिज़ाइन किया गया है। यह फ्रेमवर्क सॉफ़्टवेयर मॉड्यूल, रेडियो, प्रोटोकॉल, सिग्नल डेटा, स्क्रिप्ट, फ्लो ग्राफ, संदर्भ सामग्री और थर्ड-पार्टी उपकरणों को तेजी से एकीकृत करने के लिए बनाया गया है। FISSURE एक वर्कफ़्लो एनेबलर है जो सॉफ़्टवेयर को एक ही स्थान में रखता है और टीम को विशेष लिनक्स वितरणों के लिए साझा प्रमाणित बेसलाइन कॉन्फ़िगरेशन को साझा करता है, जिससे टीमें आसानी से तेजी से उठ सकती हैं।

FISSURE के साथ शामिल फ्रेमवर्क और उपकरण सिग्नल ऊर्जा की मौजूदगी का पता लगाने, सिग्नल की विशेषताओं को समझने, सैंपल इकट्ठा करने और विश्लेषण करने, प्रेषण और/या इंजेक्शन तकनीकों का विकसित करने, और कस्टम पेलोड या संदेश बनाने के लिए डिज़ाइन किए गए हैं। FISSURE में प्रोटोकॉल और सिग्नल सूचना की एक बढ़ती हुई पुस्तकालय है जो पहचान, पैकेट बनाने और फ़ज़िंग में मदद करने के लिए मौजूद है। ऑनलाइन आर्काइव क्षमताएं मौजूद हैं जो सिग्नल फ़ाइलें डाउनलोड करने और ट्रैफ़िक को सिम्युलेट करने और सिस्टम का परीक्षण करने के लिए प्लेलिस्ट बनाने के लिए हैं।

मित्रपूर्ण पायथन कोडबेस और उपयोगकर्ता इंटरफ़ेस नए शुरुआती उपयोगकर्ताओं को त्वरित रूप से आरएफ और रिवर्स इंजीनियरिंग के बारे में लोकप्रिय उपकरण और तकनीकों के बारे में सीखने की अनुमति देता है। साइबर सुरक्षा और इंजीनियरिंग में शिक्षक इंजीनियर इस इंजीनियरिंग का उपयोग कर सकते हैं या फ्रेमवर्क का उपयोग करके अपने खुद के वास्तविक दुनिया के अनुप्रयोगों को प्रदर्शित कर सकते हैं। डेवलपर्स और शोधकर्ता दैनिक कार्यों के लिए FISSURE का उपयोग कर सकते हैं या अपने नवीनतम समाधानों को एक व्यापक दर्शकों को प्रदर्शित करने के लिए उजागर कर सकते हैं। FISSURE की समुदाय में जागरूकता और उपयोग बढ़ती है, तो इसकी क्षमताओं की व्यापकता और इसमें शामिल तकनोलॉजी की चौड़ाई भी बढ़ेगी।

**अतिरिक्त जानकारी**

* [AIS पेज](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 स्लाइड्स](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 पेपर](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 वीडियो](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [हैक चैट ट्रांसक्रिप्ट](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## प्रारंभ करना

**समर्थित**

FISSURE में फ़ाइल नेविगेशन को आसान बनाने और कोड रेडंडेंसी को कम करने के लिए तीन शाखाएं हैं। Python2\_maint-3.7 शाखा में Python2, PyQt4 और GNU Radio 3.7 के आसार हैं; Python3\_maint-3.8 शाखा Python3, PyQt5 और GNU Radio 3.8 के आसार हैं; और Python3\_maint-3.10 शाखा Python3, PyQt5 और GNU Radio 3.10 के आसार हैं।

|   ऑपरेटिंग सिस्टम   |   FISSURE शाखा   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**कार्यान्वयन में (बीटा)**

ये ऑपरेटिंग सिस्टम अभी भी बीटा स्थिति में हैं। इनका विकास चल रहा है और कई सुविधाएं अनुपस्थित होने के लिए ज्ञात हैं। इंस्टॉलर में वस्त्राधारित आइटम मौजूद हो सकते हैं जो मौजूदा कार्यक्रमों के साथ टकराव कर सकते हैं या स्थिति हटाने तक स्थापित नहीं हो सकते हैं।

|     ऑपरेटिंग सिस्टम     |    FISSURE शाखा   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

नोट: कुछ सॉफ़्टवेयर उपकरण हर ऑपरेटिंग सिस्टम के लिए काम नहीं करते हैं। [सॉफ़्टवेयर और टकराव](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
यह PyQt सॉफ़्टवेयर की आवश्यकताओं को स्थापित करेगा जो स्थापना GUI को लॉन्च करने के लिए आवश्यक होते हैं यदि वे नहीं मिलते हैं।

अगले, अपने ऑपरेटिंग सिस्टम के साथ सबसे अच्छा विकल्प चुनें (यदि आपका ऑपरेटिंग सिस्टम विकल्प के साथ मेल खाता है तो यह स्वचालित रूप से पता लगाया जाएगा)।

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

मौजूदा टकराव से बचने के लिए FISSURE को एक साफ ऑपरेटिंग सिस्टम पर स्थापित करना सिफारिश की जाती है। FISSURE के भीतर विभिन्न उपकरणों का उपयोग करते समय त्रुटियों से बचने के लिए सभी सिफारिशित चेकबॉक्स (डिफ़ॉल्ट बटन) का चयन करें। स्थापना के दौरान कई प्रॉम्प्ट होंगे, ज्यादातर उच्चतर अनुमतियों और उपयोगकर्ता नामों के लिए पूछते हैं। यदि किसी आइटम में एक "सत्यापित करें" खंड होता है, तो स्थापक आदेश चलाएगा और चेकबॉक्स आइटम को हरा या लाल रंग में हाइलाइट करेगा आदेश द्वारा कोई त्रुटि उत्पन्न होती है। स्थापना के बाद भी वेरिफ़ाई खंड के बिना चयनित आइटम काले रंग में रहेंगे।

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**उपयोग**

एक टर्मिनल खोलें और निम्नलिखित दर्ज करें:
```
fissure
```
## विवरण

**घटक**

* डैशबोर्ड
* केंद्रीय हब (HIPRFISR)
* लक्षित संकेत पहचान (TSI)
* प्रोटोकॉल खोज (PD)
* फ्लो ग्राफ और स्क्रिप्ट निष्पादक (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**क्षमताएं**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**संकेत डिटेक्टर**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ मैनिपुलेशन**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**संकेत खोज**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**पैटर्न पहचान**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**हमले**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**फज़िलत**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**संकेत प्लेलिस्ट**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**छवि गैलरी**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**पैकेट क्राफ्टिंग**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy एकीकरण**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC कैलकुलेटर**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**लॉगिंग**_            |

**हार्डवेयर**

निम्नलिखित "समर्थित" हार्डवेयर की सूची है जिनमें विभिन्न स्तरों का एकीकरण है:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 एडाप्टर
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## पाठ

FISSURE के साथ कई मददगार गाइड शामिल हैं जिनसे विभिन्न प्रौद्योगिकियों और तकनीकों के बारे में अवगत होने में मदद मिलती है। इनमें कई ऐसे कदम शामिल हैं जो FISSURE में एकीकृत उपकरणों का उपयोग करने के लिए हैं।

* [पाठ1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [पाठ2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [पाठ3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [पाठ4: ESP बोर्ड](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [पाठ5: Radiosonde ट्रैकिंग](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [पाठ6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [पाठ7: डेटा प्रकार](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [पाठ8: कस्टम GNU रेडियो ब्लॉक](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [पाठ9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [पाठ10: हैम रेडियो परीक्षा](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [पाठ11: Wi-Fi उपकरण](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## रोडमैप

* [ ] अधिक हार्डवेयर प्रकार, आरएफ प्रोटोकॉल, संकेत पैरामीटर, विश्लेषण उपकरण जोड़ें
* [ ] अधिक ऑपरेटिंग सिस्टम का समर्थन करें
* [ ] FISSURE के चारों ओर कक्षा सामग्री विकसित करें (आरएफ हमले, Wi-Fi, GNU रेडियो, PyQt, आदि)
* [ ] एक चयन योग्य AI/ML तकनीक के साथ एक संकेत संरचक, सुविधा निकालक और संकेत वर्गीकरणकर्ता बनाएं
* [ ] अज्ञात संकेतों से बिटस्ट्रीम उत्पन्न करने के लिए पुनरावृत्ति डिमोड्यूलेशन तंत्र को लागू करें
* [ ] मुख्य FISSURE घटकों को एक सामान्य संवेदक नोड डिप्लॉयमेंट योजना में स्थानांतरित करें

## योगदान

FISSURE को सुधारने के लिए सुझावों का मजबूती से स्वागत है। यदि आपके पास निम्नलिखित के बारे में कोई विचार हैं, तो कृपया [चर्चाएं](https://github.com/ainfosec/FISSURE/discussions) पृष्ठ या डिस्कॉर्ड सर्वर में टिप्पणी छोड़ें:

* नई सुविधा सुझाव और डिज़ाइन परिवर्तन
* सॉफ़्टवेयर उपक
## सहयोग करना

FISSURE सहयोग के अवसरों की प्रस्तावना और समर्पित करने के लिए Assured Information Security, Inc. (AIS) व्यापार विकास से संपर्क करें - चाहे वह आपके सॉफ़्टवेयर को एकीकृत करने के लिए समय समर्पित करना हो, AIS के प्रतिभाशाली लोग आपके तकनीकी चुनौतियों के लिए समाधान विकसित करने हो या FISSURE को अन्य प्लेटफ़ॉर्म / एप्लिकेशन में एकीकृत करना हो।

## लाइसेंस

GPL-3.0

लाइसेंस विवरण के लिए, LICENSE फ़ाइल देखें।

## संपर्क

डिस्कॉर्ड सर्वर में शामिल हों: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

ट्विटर पर फ़ॉलो करें: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

क्रिस पूर - Assured Information Security, Inc. - poorec@ainfosec.com

व्यापार विकास - Assured Information Security, Inc. - bd@ainfosec.com

## क्रेडिट

हम इन डेवलपर्स को स्वीकार करते हैं और उनके योगदान के लिए आभारी हैं:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## प्रशंसा

इस परियोजना में उनके योगदान के लिए डॉ. सैमुअल मंत्रवादी और जोसेफ रीथ को विशेष धन्यवाद।
