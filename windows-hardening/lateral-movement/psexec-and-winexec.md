# PsExec/Winexec/ScExec

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>

## Jak działają

Proces jest opisany poniżej, ilustrując manipulację binarnymi usług w celu zdalnego wykonania na maszynie docelowej za pośrednictwem SMB:

1. **Kopiowanie binarnej usługi do udziału ADMIN$ przez SMB** jest wykonywane.
2. **Utworzenie usługi na zdalnej maszynie** jest dokonywane poprzez wskazanie binarnej usługi.
3. Usługa jest **uruchamiana zdalnie**.
4. Po zakończeniu, usługa jest **zatrzymywana, a binarna usługa jest usuwana**.

### **Proces Ręcznego Wykonywania PsExec**

Zakładając, że istnieje wykonywalny ładunek (utworzony za pomocą msfvenom i zaciemniony za pomocą Veil w celu uniknięcia wykrycia przez antywirus), o nazwie 'met8888.exe', reprezentujący ładunek meterpreter reverse\_http, podejmowane są następujące kroki:

* **Kopiowanie binarnej usługi**: Wykonywane jest skopiowanie wykonywalnego pliku do udziału ADMIN$ z wiersza polecenia, chociaż może być umieszczony w dowolnym miejscu na systemie plików, aby pozostać ukrytym.
* **Utworzenie usługi**: Korzystając z polecenia Windows `sc`, które pozwala na zapytywanie, tworzenie i usuwanie usług systemowych zdalnie, tworzona jest usługa o nazwie "meterpreter", wskazująca na przesłany binarny plik.
* **Uruchomienie usługi**: Ostatnim krokiem jest uruchomienie usługi, co najprawdopodobniej spowoduje błąd "przekroczenia czasu" z powodu tego, że binarna usługa nie jest prawdziwą binarną usługą i nie zwraca oczekiwanego kodu odpowiedzi. Ten błąd jest nieistotny, ponieważ głównym celem jest wykonanie binarnej usługi.

Obserwacja nasłuchiwacza Metasploit ujawni, że sesja została pomyślnie zainicjowana.

[Dowiedz się więcej o poleceniu `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Znajdź bardziej szczegółowe kroki w: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Możesz również użyć binarnej usługi Windows Sysinternals PsExec.exe:**

![](<../../.gitbook/assets/image (928).png>)

Możesz również użyć [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF** sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
