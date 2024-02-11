# PsExec/Winexec/ScExec

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub.**

</details>

## Jak to działa

Proces jest opisany w poniższych krokach, ilustrujących, jak manipulowane są binarne pliki usług w celu zdalnego wykonania na docelowym komputerze za pomocą SMB:

1. **Kopiowanie binarnego pliku usługi do udziału ADMIN$ przez SMB**.
2. **Tworzenie usługi na zdalnym komputerze** poprzez wskazanie binarnego pliku.
3. **Uruchamianie usługi zdalnie**.
4. Po zakończeniu usługa jest **zatrzymywana, a plik binarny jest usuwany**.

### **Proces ręcznego wykonania PsExec**

Zakładając, że istnieje wykonywalny payload (utworzony za pomocą msfvenom i zaciemniony za pomocą Veil w celu uniknięcia wykrycia przez antywirus), o nazwie 'met8888.exe', reprezentujący payload meterpreter reverse_http, podejmuje się następujące kroki:

- **Kopiowanie pliku binarnego**: Wykonywalny plik jest kopiowany do udziału ADMIN$ z wiersza polecenia, chociaż może być umieszczony w dowolnym miejscu w systemie plików, aby pozostać ukrytym.

- **Tworzenie usługi**: Wykorzystując polecenie Windows `sc`, które umożliwia zdalne zapytywanie, tworzenie i usuwanie usług systemowych Windows, tworzona jest usługa o nazwie "meterpreter", wskazująca na wczytany plik binarny.

- **Uruchamianie usługi**: Ostatnim krokiem jest uruchomienie usługi, co prawdopodobnie skutkuje błędem "time-out" z powodu tego, że plik binarny nie jest prawdziwym plikiem binarnym usługi i nie zwraca oczekiwanego kodu odpowiedzi. Ten błąd jest nieistotny, ponieważ głównym celem jest wykonanie pliku binarnego.

Obserwacja nasłuchiwacza Metasploit ujawni, że sesja została pomyślnie uruchomiona.

[Dowiedz się więcej o poleceniu `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Znajdź bardziej szczegółowe kroki na stronie: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Możesz również użyć binarnego PsExec.exe z Windows Sysinternals:**

![](<../../.gitbook/assets/image (165).png>)

Możesz również użyć [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
