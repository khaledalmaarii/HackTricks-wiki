# Wykrywanie Phishingu

<details>

<summary><strong>Zacznij od zera i stań się ekspertem od hakowania AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) albo **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Wprowadzenie

Aby wykryć próbę phishingu, ważne jest **zrozumienie technik phishingowych używanych obecnie**. Na stronie nadrzędnej tego posta znajdziesz te informacje, więc jeśli nie wiesz, jakie techniki są obecnie stosowane, polecam przejście do strony nadrzędnej i przeczytanie przynajmniej tej sekcji.

Ten post opiera się na założeniu, że **atakujący spróbują jakoś naśladować lub użyć nazwę domeny ofiary**. Jeśli twoja domena nazywa się `example.com` i zostaniesz oszukany za pomocą zupełnie innej nazwy domeny, na przykład `youwonthelottery.com`, te techniki nie odkryją tego.

## Wariacje nazw domenowych

Jest dość **łatwo** **odkryć** te **próby phishingu**, które użyją **podobnej nazwy domeny** wewnątrz e-maila.\
Wystarczy **wygenerować listę najbardziej prawdopodobnych nazw phishingowych**, jakie atakujący mogą użyć, i **sprawdzić**, czy jest **zarejestrowana**, lub po prostu sprawdzić, czy jest przypisany do niej **jakikolwiek adres IP**.

### Znajdowanie podejrzanych domen

W tym celu możesz skorzystać z dowolnego z następujących narzędzi. Zauważ, że te narzędzia będą również automatycznie wykonywać zapytania DNS, aby sprawdzić, czy domena ma przypisany jakiś adres IP:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Krótkie wyjaśnienie tej techniki znajdziesz na stronie nadrzędnej. Lub przeczytaj oryginalne badania na** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Na przykład, zmiana 1 bitu w domenie microsoft.com może przekształcić ją w _windnws.com._\
**Atakujący mogą zarejestrować jak najwięcej domen z odwróconymi bitami związanych z ofiarą, aby przekierować prawowitych użytkowników do swojej infrastruktury**.

**Wszystkie możliwe nazwy domen z odwróconymi bitami powinny być również monitorowane.**

### Podstawowe sprawdzenia

Gdy masz listę potencjalnie podejrzanych nazw domen, powinieneś je **sprawdzić** (głównie porty HTTP i HTTPS), aby **zobaczyć, czy używają jakiegoś formularza logowania podobnego** do któregoś z domen ofiary.\
Możesz również sprawdzić port 3333, aby zobaczyć, czy jest otwarty i uruchomiona instancja `gophish`.\
Interesujące jest również wiedzieć, **jak dawno została odkryta każda podejrzana domena**, im młodsza, tym większe ryzyko.\
Możesz także uzyskać **zrzuty ekranu** podejrzanej strony internetowej HTTP i/lub HTTPS, aby sprawdzić, czy jest podejrzana, a w takim przypadku **wejdź, aby się dokładniej przyjrzeć**.

### Zaawansowane sprawdzenia

Jeśli chcesz pójść o krok dalej, polecam **monitorować te podejrzane domeny i regularnie szukać kolejnych** (codziennie? to zajmuje tylko kilka sekund/minut). Powinieneś również **sprawdzić** otwarte **porty** powiązanych adresów IP i **szukać instancji `gophish` lub podobnych narzędzi** (tak, atakujący też popełniają błędy) oraz **monitorować strony internetowe HTTP i HTTPS podejrzanych domen i subdomen**, aby sprawdzić, czy skopiowano jakikolwiek formularz logowania z stron internetowych ofiary.\
Aby **zautomatyzować to**, polecam mieć listę formularzy logowania domen ofiary, przeszukać podejrzane strony internetowe i porównać każdy znaleziony formularz logowania w podejrzanych domenach z każdym formularzem logowania domeny ofiary, używając czegoś takiego jak `ssdeep`.\
Jeśli zlokalizowałeś formularze logowania podejrzanych domen, możesz spróbować **wysłać fałszywe dane logowania** i **sprawdzić, czy przekierowuje cię do domeny ofiary**.

## Nazwy domen z użyciem słów kluczowych

Strona nadrzędna również wspomina o technice wariacji nazw domenowych polegającej na umieszczeniu **nazwy domeny ofiary w większej domenie** (np. paypal-financial.com dla paypal.com).

### Transparentność certyfikatów

Nie jest możliwe zastosowanie wcześniejszego podejścia "Brute-Force", ale faktycznie **można odkryć takie próby phishingu** również dzięki transparentności certyfikatów. Za każdym razem, gdy certyfikat jest wydany przez CA, szczegóły są publicznie dostępne. Oznacza to, że czytając transparentność certyfikatów lub nawet monitorując ją, jest **możliwe znalezienie domen używających słowa kluczowego w swojej nazwie**. Na przykład, jeśli atakujący generuje certyfikat dla [https://paypal-financial.com](https://paypal-financial.com), patrząc na certyfikat, można znaleźć słowo kluczowe "paypal" i wiedzieć, że używany jest podejrzany e-mail.

Post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugeruje, że można użyć Censys do wyszukiwania certyfikatów zawierających określone słowo kluczowe i filtrowania ich według daty (tylko "nowe" certyfikaty) oraz według wydawcy CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1115).png>)

Jednakże, można "to samo" zrobić za pomocą darmowej strony internetowej [**crt.sh**](https://crt.sh). Możesz **wyszukać słowo kluczowe** i **filtrować** wyniki **według daty i CA**, jeśli chcesz.

![](<../../.gitbook/assets/image (519).png>)

Korzystając z tej ostatniej opcji, możesz nawet użyć pola Identyfikatory dopasowania, aby sprawdzić, czy jakakolwiek tożsamość z rzeczywistej domeny pasuje do którejkolwiek z podejrzanych domen (zauważ, że podejrzana domena może być fałszywym wynikiem).

**Inną alternatywą** jest fantastyczny projekt o nazwie [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream dostarcza strumień w czasie rzeczywistym nowo generowanych certyfikatów, które można użyć do wykrywania określonych słów kluczowych w (prawie) czasie rzeczywistym. Faktycznie istnieje projekt o nazwie [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher), który robi dokładnie to.
### **Nowe domeny**

**Ostatnią alternatywą** jest zebranie listy **nowo zarejestrowanych domen** dla niektórych TLD ([Whoxy](https://www.whoxy.com/newly-registered-domains/) oferuje takie usługi) i **sprawdzenie słów kluczowych w tych domenach**. Jednakże długie domeny zazwyczaj używają jednej lub więcej subdomen, dlatego słowo kluczowe nie pojawi się wewnątrz FLD i nie będzie można znaleźć subdomeny phishingowej.
