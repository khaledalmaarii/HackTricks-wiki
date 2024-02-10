<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


피싱 평가를 위해 때로는 웹사이트를 완전히 **복제하는 것**이 유용할 수 있습니다.

복제된 웹사이트에는 사용자의 탭을 "제어"하기 위한 BeEF 후크와 같은 페이로드를 추가할 수도 있습니다.

이를 위해 사용할 수 있는 다양한 도구가 있습니다:

## wget
```text
wget -mk -nH
```
## goclone

goclone은 웹 사이트를 복제하는 데 사용되는 도구입니다. 이 도구를 사용하면 원본 웹 사이트의 외관과 동작을 완벽하게 복제할 수 있습니다. 이를 통해 공격자는 피싱 공격을 수행하여 사용자의 개인 정보를 탈취하거나 악성 코드를 배포할 수 있습니다.

goclone을 사용하여 웹 사이트를 복제하는 방법은 다음과 같습니다.

1. goclone을 설치하고 실행합니다.
2. 복제하려는 웹 사이트의 URL을 지정합니다.
3. goclone은 웹 사이트의 모든 파일과 폴더를 다운로드합니다.
4. 원본 웹 사이트의 HTML, CSS, JavaScript 등의 파일을 수정하여 피싱 공격에 적합하게 조작합니다.
5. 수정된 파일을 호스팅하고 공격자는 피싱 링크를 통해 사용자를 유인합니다.

goclone은 피싱 공격에 사용되는 강력한 도구이므로 합법적인 목적으로만 사용해야 합니다. 이 도구를 사용하여 개인 정보를 탈취하거나 악의적인 목적을 가진 행위는 불법입니다.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## 사회 공학 도구킷

### Clone a Website

### 웹사이트 복제하기

One of the most effective ways to perform phishing attacks is by cloning a legitimate website. This technique involves creating an identical copy of a target website, including its design, layout, and functionality. By doing so, attackers can trick users into entering their sensitive information, such as login credentials or credit card details, on the cloned website.

피싱 공격을 수행하는 가장 효과적인 방법 중 하나는 합법적인 웹사이트를 복제하는 것입니다. 이 기술은 대상 웹사이트의 디자인, 레이아웃 및 기능을 포함한 동일한 사본을 생성하는 것을 포함합니다. 이렇게 함으로써 공격자는 사용자들을 속여 로그인 자격 증명이나 신용카드 정보와 같은 민감한 정보를 복제된 웹사이트에 입력하도록 유도할 수 있습니다.

To clone a website, you can use tools like HTTrack or Wget to download the entire website's content, including HTML, CSS, JavaScript, and images. Once you have the website's files, you can host them on a web server or a cloud storage service.

웹사이트를 복제하기 위해서는 HTTrack 또는 Wget과 같은 도구를 사용하여 HTML, CSS, JavaScript 및 이미지를 포함한 전체 웹사이트 콘텐츠를 다운로드할 수 있습니다. 웹사이트 파일을 얻은 후에는 웹 서버나 클라우드 스토리지 서비스에 호스팅할 수 있습니다.

To make the cloned website appear legitimate, you will need to modify the HTML and CSS files to match the original website's design. This includes copying the original website's logo, colors, fonts, and layout. Additionally, you may need to modify the website's functionality to capture user input and send it to a remote server.

복제된 웹사이트가 합법적으로 보이도록 하기 위해서는 HTML 및 CSS 파일을 수정하여 원래 웹사이트의 디자인과 일치하도록 해야 합니다. 이는 원래 웹사이트의 로고, 색상, 글꼴 및 레이아웃을 복사하는 것을 포함합니다. 또한 사용자 입력을 캡처하고 원격 서버로 전송하기 위해 웹사이트의 기능을 수정해야 할 수도 있습니다.

It is important to note that cloning a website for malicious purposes is illegal and unethical. This technique should only be used for educational or authorized testing purposes, such as penetration testing or security awareness training.

악의적인 목적으로 웹사이트를 복제하는 것은 불법이며 윤리적으로 문제가 됩니다. 이 기술은 펜테스팅이나 보안 인식 훈련과 같은 교육적이거나 승인된 테스트 목적으로만 사용되어야 합니다.
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
