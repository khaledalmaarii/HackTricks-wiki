# Extensões do Sistema macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Extensões do Sistema / Framework de Segurança de Ponta

Ao contrário das Extensões de Kernel, as **Extensões do Sistema são executadas no espaço do usuário** em vez do espaço do kernel, reduzindo o risco de uma falha do sistema devido a mau funcionamento da extensão.

<figure><img src="../../../.gitbook/assets/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Existem três tipos de extensões do sistema: Extensões **DriverKit**, Extensões de **Rede** e Extensões de **Segurança de Ponta**.

### **Extensões DriverKit**

DriverKit é um substituto para extensões de kernel que **fornecem suporte de hardware**. Ele permite que drivers de dispositivos (como USB, Serial, NIC e HID drivers) sejam executados no espaço do usuário em vez do espaço do kernel. O framework DriverKit inclui **versões no espaço do usuário de certas classes do I/O Kit**, e o kernel encaminha eventos normais do I/O Kit para o espaço do usuário, oferecendo um ambiente mais seguro para esses drivers serem executados.

### **Extensões de Rede**

As Extensões de Rede fornecem a capacidade de personalizar comportamentos de rede. Existem vários tipos de Extensões de Rede:

* **Proxy de Aplicativo**: Isso é usado para criar um cliente VPN que implementa um protocolo VPN personalizado orientado ao fluxo. Isso significa que ele lida com o tráfego de rede com base em conexões (ou fluxos) em vez de pacotes individuais.
* **Túnel de Pacotes**: Isso é usado para criar um cliente VPN que implementa um protocolo VPN personalizado orientado a pacotes. Isso significa que ele lida com o tráfego de rede com base em pacotes individuais.
* **Filtro de Dados**: Isso é usado para filtrar "fluxos" de rede. Pode monitorar ou modificar dados de rede no nível do fluxo.
* **Filtro de Pacotes**: Isso é usado para filtrar pacotes de rede individuais. Pode monitorar ou modificar dados de rede no nível do pacote.
* **Proxy DNS**: Isso é usado para criar um provedor DNS personalizado. Pode ser usado para monitorar ou modificar solicitações e respostas DNS.

## Framework de Segurança de Ponta

A Segurança de Ponta é um framework fornecido pela Apple no macOS que fornece um conjunto de APIs para segurança do sistema. É destinado ao uso por **fornecedores de segurança e desenvolvedores para construir produtos que possam monitorar e controlar a atividade do sistema** para identificar e proteger contra atividades maliciosas.

Este framework fornece uma **coleção de APIs para monitorar e controlar a atividade do sistema**, como execuções de processos, eventos do sistema de arquivos, eventos de rede e kernel.

O núcleo deste framework é implementado no kernel, como uma Extensão de Kernel (KEXT) localizada em **`/System/Library/Extensions/EndpointSecurity.kext`**. Esta KEXT é composta por vários componentes principais:

* **EndpointSecurityDriver**: Atua como o "ponto de entrada" para a extensão do kernel. É o principal ponto de interação entre o SO e o framework de Segurança de Ponta.
* **EndpointSecurityEventManager**: Este componente é responsável por implementar ganchos do kernel. Ganchos do kernel permitem que o framework monitore eventos do sistema interceptando chamadas do sistema.
* **EndpointSecurityClientManager**: Gerencia a comunicação com clientes no espaço do usuário, mantendo o controle de quais clientes estão conectados e precisam receber notificações de eventos.
* **EndpointSecurityMessageManager**: Envia mensagens e notificações de eventos para clientes no espaço do usuário.

Os eventos que o framework de Segurança de Ponta pode monitorar são categorizados em:

* Eventos de arquivo
* Eventos de processo
* Eventos de soquete
* Eventos de kernel (como carregar/descarregar uma extensão de kernel ou abrir um dispositivo I/O Kit)

### Arquitetura do Framework de Segurança de Ponta

<figure><img src="../../../.gitbook/assets/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

A **comunicação no espaço do usuário** com o framework de Segurança de Ponta ocorre por meio da classe IOUserClient. Duas subclasses diferentes são usadas, dependendo do tipo de chamador:

* **EndpointSecurityDriverClient**: Isso requer a permissão `com.apple.private.endpoint-security.manager`, que é detida apenas pelo processo do sistema `endpointsecurityd`.
* **EndpointSecurityExternalClient**: Isso requer a permissão `com.apple.developer.endpoint-security.client`. Isso seria tipicamente usado por software de segurança de terceiros que precisa interagir com o framework de Segurança de Ponta.

As Extensões de Segurança de Ponta:**`libEndpointSecurity.dylib`** é a biblioteca C que as extensões do sistema usam para se comunicar com o kernel. Esta biblioteca usa o I/O Kit (`IOKit`) para se comunicar com a KEXT de Segurança de Ponta.

**`endpointsecurityd`** é um daemon do sistema chave envolvido na gestão e lançamento de extensões do sistema de segurança de ponta, especialmente durante o processo de inicialização inicial. **Apenas extensões do sistema** marcadas com **`NSEndpointSecurityEarlyBoot`** em seu arquivo `Info.plist` recebem este tratamento de inicialização inicial.

Outro daemon do sistema, **`sysextd`**, **valida as extensões do sistema** e as move para as localizações adequadas do sistema. Em seguida, solicita ao daemon relevante para carregar a extensão. O **`SystemExtensions.framework`** é responsável por ativar e desativar as extensões do sistema.

## Bypassing ESF

ESF é usado por ferramentas de segurança que tentarão detectar um red teamer, então qualquer informação sobre como isso poderia ser evitado soa interessante.

### CVE-2021-30965

A questão é que a aplicação de segurança precisa ter as **permissões de Acesso Total ao Disco**. Portanto, se um atacante pudesse remover isso, ele poderia impedir que o software fosse executado:
```bash
tccutil reset All
```
Para **mais informações** sobre esse bypass e outros relacionados, confira a palestra [#OBTS v5.0: "O Calcanhar de Aquiles da Segurança de Endpoint" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

No final, isso foi corrigido dando a nova permissão **`kTCCServiceEndpointSecurityClient`** ao aplicativo de segurança gerenciado por **`tccd`** para que o `tccutil` não limpe suas permissões, impedindo que ele seja executado.

## Referências

* [**OBTS v3.0: "Segurança e Insegurança de Endpoint" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
