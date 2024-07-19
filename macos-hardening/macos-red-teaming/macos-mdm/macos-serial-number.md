# macOS Serial Number

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## 기본 정보

2010년 이후의 Apple 기기는 **12자리 알파벳 숫자**로 구성된 일련 번호를 가지고 있으며, 각 세그먼트는 특정 정보를 전달합니다:

- **첫 3자리**: **제조 위치**를 나타냅니다.
- **4번째 및 5번째 문자**: **제조 연도 및 주**를 나타냅니다.
- **6번째부터 8번째 문자**: 각 기기에 대한 **고유 식별자** 역할을 합니다.
- **마지막 4자리**: **모델 번호**를 지정합니다.

예를 들어, 일련 번호 **C02L13ECF8J2**는 이 구조를 따릅니다.

### **제조 위치 (첫 3자리)**
특정 코드는 특정 공장을 나타냅니다:
- **FC, F, XA/XB/QP/G8**: 미국의 다양한 위치.
- **RN**: 멕시코.
- **CK**: 아일랜드 코크.
- **VM**: 체코 공화국 폭스콘.
- **SG/E**: 싱가포르.
- **MB**: 말레이시아.
- **PT/CY**: 한국.
- **EE/QT/UV**: 대만.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: 중국의 다양한 위치.
- **C0, C3, C7**: 중국의 특정 도시.
- **RM**: 리퍼비시된 기기.

### **제조 연도 (4번째 문자)**
이 문자는 'C' (2010년 상반기)에서 'Z' (2019년 하반기)까지 다양하며, 서로 다른 문자가 서로 다른 반년 기간을 나타냅니다.

### **제조 주 (5번째 문자)**
숫자 1-9는 주 1-9에 해당합니다. 문자 C-Y (모음과 'S' 제외)는 주 10-27을 나타냅니다. 연도의 하반기에는 이 숫자에 26이 추가됩니다.

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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
