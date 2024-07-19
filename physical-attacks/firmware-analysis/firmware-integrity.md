{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Firmware Integrity

**Özel firmware ve/veya derlenmiş ikili dosyalar, bütünlük veya imza doğrulama hatalarını istismar etmek için yüklenebilir.** Aşağıdaki adımlar arka kapı bind shell derlemesi için izlenebilir:

1. Firmware, firmware-mod-kit (FMK) kullanılarak çıkarılabilir.
2. Hedef firmware mimarisi ve endianlığı belirlenmelidir.
3. Ortam için Buildroot veya diğer uygun yöntemler kullanılarak bir çapraz derleyici oluşturulabilir.
4. Arka kapı, çapraz derleyici kullanılarak oluşturulabilir.
5. Arka kapı, çıkarılan firmware /usr/bin dizinine kopyalanabilir.
6. Uygun QEMU ikili dosyası, çıkarılan firmware rootfs'ye kopyalanabilir.
7. Arka kapı, chroot ve QEMU kullanılarak taklit edilebilir.
8. Arka kapıya netcat aracılığıyla erişilebilir.
9. QEMU ikili dosyası, çıkarılan firmware rootfs'den kaldırılmalıdır.
10. Değiştirilen firmware, FMK kullanılarak yeniden paketlenebilir.
11. Arka kapılı firmware, firmware analiz aracı (FAT) ile taklit edilerek ve hedef arka kapı IP'sine ve portuna netcat kullanarak bağlanarak test edilebilir.

Eğer dinamik analiz, önyükleyici manipülasyonu veya donanım güvenlik testi yoluyla bir root shell elde edilmişse, implantlar veya ters shell gibi önceden derlenmiş kötü niyetli ikili dosyalar çalıştırılabilir. Metasploit çerçevesi ve 'msfvenom' gibi otomatik yük/implant araçları aşağıdaki adımlar kullanılarak kullanılabilir:

1. Hedef firmware mimarisi ve endianlığı belirlenmelidir.
2. Msfvenom, hedef yükü, saldırgan ana bilgisayar IP'sini, dinleme port numarasını, dosya türünü, mimariyi, platformu ve çıktı dosyasını belirtmek için kullanılabilir.
3. Yük, ele geçirilmiş cihaza aktarılabilir ve yürütme izinlerinin olduğundan emin olunabilir.
4. Metasploit, msfconsole başlatarak ve ayarları yükleye göre yapılandırarak gelen istekleri işlemek için hazırlanabilir.
5. Meterpreter ters shell, ele geçirilmiş cihazda çalıştırılabilir.
6. Meterpreter oturumları açıldıkça izlenebilir.
7. İstismar sonrası faaliyetler gerçekleştirilebilir.

Mümkünse, başlangıç betiklerinde bulunan zafiyetler, yeniden başlatmalar arasında bir cihaza kalıcı erişim sağlamak için istismar edilebilir. Bu zafiyetler, başlangıç betiklerinin, güvenilmeyen montajlı konumlarda bulunan kodlara atıfta bulunması, [sembolik bağlantı](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data) yapması veya bunlara bağımlı olması durumunda ortaya çıkar; bu konumlar, kök dosya sistemleri dışında veri depolamak için kullanılan SD kartlar ve flash hacimleri gibi yerlerdir.

## References
* For further information check [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
