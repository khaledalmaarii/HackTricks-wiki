# Infravermelho

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Como Funciona o Infravermelho <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**A luz infravermelha é invisível para os humanos**. O comprimento de onda do IR é de **0,7 a 1000 microns**. Controles remotos domésticos usam um sinal de IR para transmissão de dados e operam na faixa de comprimento de onda de 0,75..1,4 microns. Um microcontrolador no controle faz um LED infravermelho piscar com uma frequência específica, transformando o sinal digital em um sinal de IR.

Para receber sinais de IR, é usado um **fotoreceptor**. Ele **converte a luz IR em pulsos de tensão**, que já são **sinais digitais**. Geralmente, há um **filtro de luz escura dentro do receptor**, que permite **apenas a passagem do comprimento de onda desejado** e elimina ruídos.

### Variedade de Protocolos IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Os protocolos IR diferem em 3 fatores:

* codificação de bits
* estrutura de dados
* frequência portadora — geralmente na faixa de 36..38 kHz

#### Formas de codificação de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codificação por Distância de Pulso**

Os bits são codificados modulando a duração do espaço entre os pulsos. A largura do pulso em si é constante.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Codificação por Largura de Pulso**

Os bits são codificados pela modulação da largura do pulso. A largura do espaço após o pulso é constante.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Codificação de Fase**

Também é conhecida como codificação Manchester. O valor lógico é definido pela polaridade da transição entre o pulso e o espaço. "Espaço para pulso" denota lógica "0", "pulso para espaço" denota lógica "1".

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Combinação dos anteriores e outras exóticas**

{% hint style="info" %}
Existem protocolos IR que estão **tentando se tornar universais** para vários tipos de dispositivos. Os mais famosos são RC5 e NEC. Infelizmente, o mais famoso **não significa o mais comum**. No meu ambiente, encontrei apenas dois controles remotos NEC e nenhum RC5.

Os fabricantes adoram usar seus próprios protocolos IR únicos, mesmo dentro da mesma gama de dispositivos (por exemplo, TV-boxes). Portanto, controles de diferentes empresas e às vezes de diferentes modelos da mesma empresa, são incapazes de trabalhar com outros dispositivos do mesmo tipo.
{% endhint %}

### Explorando um sinal de IR

A maneira mais confiável de ver como o sinal de IR do controle remoto se parece é usar um osciloscópio. Ele não demodula ou inverte o sinal recebido, ele é apenas exibido "como é". Isso é útil para testes e depuração. Mostrarei o sinal esperado no exemplo do protocolo IR NEC.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Geralmente, há um preâmbulo no início de um pacote codificado. Isso permite que o receptor determine o nível de ganho e o fundo. Há também protocolos sem preâmbulo, por exemplo, Sharp.

Em seguida, os dados são transmitidos. A estrutura, o preâmbulo e o método de codificação de bits são determinados pelo protocolo específico.

O **protocolo IR NEC** contém um comando curto e um código de repetição, que é enviado enquanto o botão é pressionado. Tanto o comando quanto o código de repetição têm o mesmo preâmbulo no início.

O **comando NEC**, além do preâmbulo, consiste em um byte de endereço e um byte de número de comando, pelo qual o dispositivo entende o que precisa ser executado. Os bytes de endereço e número de comando são duplicados com valores inversos, para verificar a integridade da transmissão. Há um bit de parada adicional no final do comando.

O **código de repetição** tem um "1" após o preâmbulo, que é um bit de parada.

Para **lógica "0" e "1"** NEC usa Codificação por Distância de Pulso: primeiro, um pulso é transmitido após o qual há uma pausa, seu comprimento define o valor do bit.

### Ar Condicionados

Diferentemente de outros controles remotos, **os ar condicionados não transmitem apenas o código do botão pressionado**. Eles também **transmitem todas as informações** quando um botão é pressionado para garantir que a **máquina de ar condicionado e o controle remoto estejam sincronizados**.\
Isso evitará que uma máquina ajustada para 20ºC seja aumentada para 21ºC com um controle remoto, e então, quando outro controle remoto, que ainda tem a temperatura como 20ºC, for usado para aumentar mais a temperatura, ele "aumentará" para 21ºC (e não para 22ºC pensando que está em 21ºC).

### Ataques

Você pode atacar Infravermelho com Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Referências

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
