यदि आपके पास एक USB कनेक्शन का pcap है जिसमें बहुत सारी बाधाएं हैं, तो शायद यह एक USB कीबोर्ड कनेक्शन हो सकती है।

एक वायरशार्क फ़िल्टर जैसे इसका उपयोगी हो सकता है: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

यह महत्वपूर्ण हो सकता है कि "02" से शुरू होने वाला डेटा शिफ्ट का उपयोग करके दबाया जाता है।

आप इसे विश्लेषण करने के लिए और कुछ स्क्रिप्ट खोजने के लिए अधिक जानकारी पढ़ सकते हैं:

* [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
* [https://github.com/tanc7/HacktheBox\_Deadly\_Arthropod\_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
