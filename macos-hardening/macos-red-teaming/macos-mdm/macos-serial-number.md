# macOS 시리얼 번호

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>


## 기본 정보

2010년 이후의 Apple 기기는 **12개의 알파벳과 숫자로 이루어진 시리얼 번호**를 가지며, 각 세그먼트는 특정 정보를 전달합니다:

- **첫 3자리**: **제조 위치**를 나타냅니다.
- **4번째와 5번째 자리**: **제조 연도와 주**를 나타냅니다.
- **6번째부터 8번째 자리**: 각 기기의 **고유 식별자**로 사용됩니다.
- **마지막 4자리**: **모델 번호**를 지정합니다.

예를 들어, 시리얼 번호 **C02L13ECF8J2**는 이 구조를 따릅니다.

### **제조 위치 (첫 3자리)**
특정 코드는 특정 공장을 나타냅니다:
- **FC, F, XA/XB/QP/G8**: 미국의 다양한 위치.
- **RN**: 멕시코.
- **CK**: 아일랜드의 코크.
- **VM**: 체코 공화국의 Foxconn.
- **SG/E**: 싱가포르.
- **MB**: 말레이시아.
- **PT/CY**: 한국.
- **EE/QT/UV**: 대만.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: 중국의 다양한 위치.
- **C0, C3, C7**: 중국의 특정 도시.
- **RM**: 재생산된 기기.

### **제조 연도 (4번째 자리)**
이 문자는 'C' (2010년 상반기를 나타냄)에서 'Z' (2019년 하반기를 나타냄)까지 다양하며, 다른 문자는 반기별 기간을 나타냅니다.

### **제조 주 (5번째 자리)**
숫자 1-9는 주 1-9에 해당합니다. 문자 C-Y (모음과 'S'를 제외한)는 주 10-27을 나타냅니다. 하반기에는 이 숫자에 26이 추가됩니다.

### **고유 식별자 (6번째부터 8번째 자리)**
이 세 자리 숫자는 동일한 모델과 일괄 생산 기기라도 고유한 시리얼 번호를 가지도록 합니다.

### **모델 번호 (마지막 4자리)**
이 숫자는 기기의 특정 모델을 식별합니다.

### 참고

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
