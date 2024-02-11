# Atak xpc\_connection\_get\_audit\_token na macOS

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Aby uzyskać więcej informacji, sprawdź oryginalny post: [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)**. Oto streszczenie:


## Podstawowe informacje o komunikacji międzyprocesowej Mach

Jeśli nie wiesz, czym są komunikaty Mach, zacznij od sprawdzenia tej strony:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Na razie pamiętaj, że ([definicja stąd](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Komunikaty Mach są wysyłane przez _port Mach_, który jest kanałem komunikacji **jednego odbiorcy, wielu nadawców**, wbudowanym w jądro Mach. **Wiele procesów może wysyłać wiadomości** do portu Mach, ale w dowolnym momencie **tylko jeden proces może z niego czytać**. Podobnie jak deskryptory plików i gniazdka, porty Mach są przydzielane i zarządzane przez jądro, a procesy widzą tylko liczbę całkowitą, którą mogą użyć, aby wskazać jądrze, który z ich portów Mach chcą użyć.

## Połączenie XPC

Jeśli nie wiesz, jak nawiązać połączenie XPC, sprawdź:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Podsumowanie podatności

Warto wiedzieć, że **abstrakcja XPC to połączenie jeden do jednego**, ale oparte jest na technologii, która **może mieć wiele nadawców, więc:**

* Porty Mach są jednym odbiorcą, **wieloma nadawcami**.
* Token audytu połączenia XPC to token audytu **skopiowany z ostatnio otrzymanej wiadomości**.
* Uzyskanie **tokena audytu** połączenia XPC jest kluczowe dla wielu **kontroli bezpieczeństwa**.

Chociaż poprzednia sytuacja wydaje się obiecująca, istnieją pewne scenariusze, w których to nie spowoduje problemów ([stąd](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Tokeny audytu są często używane do sprawdzenia autoryzacji w celu zdecydowania, czy zaakceptować połączenie. Ponieważ dzieje się to za pomocą wiadomości do portu usługi, **jeszcze nie zostało nawiązane połączenie**. Więcej wiadomości na tym porcie będzie po prostu obsługiwanych jako dodatkowe żądania połączenia. Więc **kontrole przed zaakceptowaniem połączenia nie są podatne** (to oznacza również, że wewnątrz `-listener:shouldAcceptNewConnection:` token audytu jest bezpieczny). Szukamy więc **połączeń XPC, które weryfikują konkretne działania**.
* Obsługiwane są procedury obsługi zdarzeń XPC. Oznacza to, że procedura obsługi zdarzeń dla jednej wiadomości musi zostać zakończona przed jej wywołaniem dla następnej, nawet na równoległych kolejkach dystrybucji. Więc wewnątrz **procedury obsługi zdarzeń XPC token audytu nie może zostać nadpisany** przez inne normalne (nie-odpowiedziowe!) wiadomości.

Istnieją dwa różne sposoby, w jakie można wykorzystać tę podatność:

1. Wariant 1:
* **Exploit** **łączy się** z usługą **A** i usługą **B**.
* Usługa **B** może wywołać **uprzywilejowaną funkcjonalność** w usłudze A, do której użytkownik nie ma dostępu.
* Usługa **A** wywołuje **`xpc_connection_get_audit_token`** podczas **nie**-obsługi zdarzenia dla połączenia w **`dispatch_async`**.
* Więc **inna** wiadomość może **nadpisać Token Audytu**, ponieważ jest wysyłana asynchronicznie poza procedurą obsługi zdarzeń.
* Exploit przekazuje usłudze **B prawo do wysyłania** wiadomości do usługi **A**.
* Usługa **B** faktycznie **wysyła** wiadomości do usługi **A**.
* Exploit próbuje **wywołać** **uprzywilejowaną akcję**. W usłudze RC **A sprawdza** autoryzację tej **akcji**, podczas gdy **usługa B nadpisała Token Audytu** (dając exploit dostęp do wywołania uprzywilejowanej akcji).
2. Wariant 2:
* Usługa **B** może wywołać **uprzywilejowaną funkcjonalność** w usłudze A, do której użytkownik nie ma dostępu.
* Exploit łączy się z usługą **A**, która **wysyła** exploitowi wiadomość oczekującą na odpowiedź w określonym **porcie odpowiedzi**.
* Exploit wysyła usłudze **B** wiadomość przekazującą **ten port odpowiedzi**.
* Gdy usługa **B odpowiada**, wysyła wiadomość do usługi **A**, **podczas gdy** exploit wysyła inną **wiadomość do usługi A**, próbując **osiągnąć uprzywilejowaną funkcjonalność** i oczekując, że odpowiedź od usługi B nadpisze Token Audytu w idealnym momencie (Race Condition).

## Wariant 1: wywołanie
4. Następny krok polega na poleceniu `diagnosticd` rozpoczęcia monitorowania wybranego procesu (potencjalnie procesu użytkownika). Jednocześnie wysyłane jest dużo rutynowych wiadomości 1004 do `smd`. Celem jest zainstalowanie narzędzia z podwyższonymi uprawnieniami.
5. Ta czynność wywołuje warunkowe wyścigi w funkcji `handle_bless`. Ważne jest, aby wywołanie funkcji `xpc_connection_get_pid` zwróciło PID procesu użytkownika (ponieważ narzędzie z podwyższonymi uprawnieniami znajduje się w pakiecie aplikacji użytkownika). Jednak funkcja `xpc_connection_get_audit_token`, a konkretnie podprogram `connection_is_authorized`, musi odnosić się do tokenu audytu należącego do `diagnosticd`.

## Wariant 2: przekazywanie odpowiedzi

W środowisku XPC (Cross-Process Communication) obsługa komunikatów odpowiedzi ma unikalne zachowanie, chociaż obsługa zdarzeń nie jest wykonywana równocześnie. Istnieją dwie różne metody wysyłania komunikatów, które oczekują odpowiedzi:

1. **`xpc_connection_send_message_with_reply`**: Tutaj komunikat XPC jest odbierany i przetwarzany w wyznaczonej kolejce.
2. **`xpc_connection_send_message_with_reply_sync`**: W przeciwnym razie, w tej metodzie komunikat XPC jest odbierany i przetwarzany w bieżącej kolejce dyspozytorskiej.

Ta różnica jest istotna, ponieważ umożliwia **równoczesne analizowanie pakietów odpowiedzi wraz z wykonywaniem obsługi zdarzeń XPC**. Warto zauważyć, że chociaż funkcja `_xpc_connection_set_creds` implementuje blokowanie w celu zabezpieczenia przed częściowym nadpisaniem tokenu audytu, nie rozszerza tej ochrony na cały obiekt połączenia. W rezultacie powstaje podatność, w której token audytu może zostać zastąpiony w okresie między analizą pakietu a wykonaniem jego obsługi zdarzeń.

Aby wykorzystać tę podatność, wymagane jest następujące przygotowanie:

- Dwa usługi mach, oznaczone jako **`A`** i **`B`**, obie z możliwością nawiązania połączenia.
- Usługa **`A`** powinna zawierać sprawdzenie autoryzacji dla określonej akcji, którą tylko **`B`** może wykonać (aplikacja użytkownika nie może).
- Usługa **`A`** powinna wysłać komunikat, który oczekuje odpowiedzi.
- Użytkownik może wysłać wiadomość do **`B`**, na którą odpowie.

Proces wykorzystania tej podatności obejmuje następujące kroki:

1. Oczekiwanie na wysłanie przez usługę **`A`** komunikatu, który oczekuje odpowiedzi.
2. Zamiast bezpośredniego odpowiedzenia na **`A`**, port odpowiedzi jest przejęty i używany do wysłania wiadomości do usługi **`B`**.
3. Następnie wysyłana jest wiadomość dotycząca zabronionej akcji, z oczekiwaniem, że zostanie przetworzona równocześnie z odpowiedzią od **`B`**.

Poniżej przedstawiono wizualne przedstawienie opisanego scenariusza ataku:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)


<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemy z odkrywaniem

- **Trudności w lokalizacji instancji**: Wyszukiwanie użycia `xpc_connection_get_audit_token` było trudne zarówno statycznie, jak i dynamicznie.
- **Metodologia**: Do przechwycenia funkcji `xpc_connection_get_audit_token` użyto narzędzia Frida, filtrowano wywołania niepochodzące od obsługi zdarzeń. Jednak ta metoda była ograniczona do przechwyconego procesu i wymagała aktywnego użycia.
- **Narzędzia analizy**: Narzędzia takie jak IDA/Ghidra były używane do badania dostępnych usług mach, ale proces był czasochłonny i komplikowany przez wywołania związane z pamięcią podręczną dyld.
- **Ograniczenia skryptów**: Próby zautomatyzowania analizy wywołań `xpc_connection_get_audit_token` z bloków `dispatch_async` były utrudnione przez złożoność analizy bloków i interakcje z pamięcią podręczną dyld.

## Naprawa <a href="#the-fix" id="the-fix"></a>

- **Zgłoszone problemy**: Zgłoszono raport do Apple, w którym opisano ogólne i konkretne problemy związane z `smd`.
- **Odpowiedź Apple**: Apple rozwiązało problem w `smd`, zamieniając `xpc_connection_get_audit_token` na `xpc_dictionary_get_audit_token`.
- **Charakter naprawy**: Funkcja `xpc_dictionary_get_audit_token` jest uważana za bezpieczną, ponieważ pobiera token audytu bezpośrednio z wiadomości mach powiązanej z otrzymaną wiadomością XPC. Jednak nie jest częścią publicznego interfejsu API, podobnie jak `xpc_connection_get_audit_token`.
- **Brak szerszej naprawy**: Niejasne jest, dlaczego Apple nie zaimplementowało bardziej kompleksowej naprawy, takiej jak odrzucanie wiadomości niezgodnych z zapisanym tokenem audytu połączenia. Może to być spowodowane możliwością zmiany prawidłowego tokenu audytu w określonych scenariuszach (np. przy użyciu `setuid`).
- **Aktualny status**: Problem nadal występuje w iOS 17 i macOS 14, co stanowi wyzwanie dla osób starających się go zidentyfikować i zrozumieć.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
