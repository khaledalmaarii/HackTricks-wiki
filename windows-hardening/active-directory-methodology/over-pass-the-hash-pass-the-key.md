# Over Pass the Hash/Pass the Key

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Overpass The Hash/Pass The Key (PTK)

O ataque **Overpass The Hash/Pass The Key (PTK)** é projetado para ambientes onde o protocolo NTLM tradicional é restrito e a autenticação Kerberos tem precedência. Esse ataque aproveita o hash NTLM ou chaves AES de um usuário para solicitar tickets Kerberos, permitindo acesso não autorizado a recursos dentro de uma rede.

Para executar esse ataque, o primeiro passo envolve adquirir o hash NTLM ou a senha da conta do usuário alvo. Ao garantir essas informações, um Ticket Granting Ticket (TGT) para a conta pode ser obtido, permitindo que o atacante acesse serviços ou máquinas para os quais o usuário tem permissões.

O processo pode ser iniciado com os seguintes comandos:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Para cenários que necessitam de AES256, a opção `-aesKey [chave AES]` pode ser utilizada. Além disso, o ticket adquirido pode ser empregado com várias ferramentas, incluindo smbexec.py ou wmiexec.py, ampliando o escopo do ataque.

Problemas encontrados, como _PyAsn1Error_ ou _KDC cannot find the name_, são tipicamente resolvidos atualizando a biblioteca Impacket ou utilizando o nome do host em vez do endereço IP, garantindo compatibilidade com o KDC do Kerberos.

Uma sequência de comandos alternativa usando o Rubeus.exe demonstra outro aspecto dessa técnica:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Este método espelha a abordagem **Pass the Key**, com foco na apropriação e utilização direta do ticket para fins de autenticação. É crucial notar que a inicialização de uma solicitação de TGT aciona o evento `4768: A Kerberos authentication ticket (TGT) was requested`, indicando o uso do RC4-HMAC por padrão, embora sistemas Windows modernos prefiram o AES256.

Para conformidade com a segurança operacional e uso do AES256, o seguinte comando pode ser aplicado:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Referências

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
