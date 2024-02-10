# macOS Apple Scriptleri

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

## Apple Scriptleri

Bu, **uzaktaki işlemlerle etkileşimde bulunmak için kullanılan bir betik dili**dir. Başka işlemlere bazı eylemler yapmaları için sormak oldukça kolaydır. **Kötü amaçlı yazılımlar**, diğer işlemler tarafından dışa aktarılan işlevleri kötüye kullanabilir.\
Örneğin, bir kötü amaçlı yazılım, tarayıcıda açılan sayfalara **keyfi JS kodu enjekte** edebilir. Veya kullanıcıdan istenen bazı izinlere **otomatik olarak tıklayabilir**.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
İşte bazı örnekler: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Applescript kullanarak kötü amaçlı yazılım hakkında daha fazla bilgiyi [**burada**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) bulabilirsiniz.

Apple scriptleri kolayca "**derlenebilir**". Bu sürümler `osadecompile` ile kolayca "**derlenebilir**".

Ancak, bu scriptler aynı zamanda **"Salt okunur" olarak dışa aktarılabilir** ( "Dışa aktar..." seçeneğiyle):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
Ve bu durumda içerik, `osadecompile` ile bile decompile edilemez.

Ancak, yine de bu tür yürütülebilir dosyaları anlamak için kullanılabilecek bazı araçlar vardır, [**daha fazla bilgi için bu araştırmayı okuyun**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) aracı, [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) ile birlikte, betiğin nasıl çalıştığını anlamak için çok faydalı olacaktır.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
