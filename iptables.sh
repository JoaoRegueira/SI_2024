sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -F

# Limpar regras e cadeias existentes
sudo iptables -F
sudo iptables -X

# Definir política padrão para DROP (bloquear todo o tráfego de entrada) em todas as cadeias
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

#Permite receber comunicação das maquinas descritas em baixo 
sudo /sbin/iptables -A INPUT -s 10.121.52.14 -j ACCEPT
sudo /sbin/iptables -A INPUT -s 10.121.52.15 -j ACCEPT
sudo /sbin/iptables -A INPUT -s 10.121.52.16 -j ACCEPT
sudo /sbin/iptables -A INPUT -s 10.121.72.23 -j ACCEPT
sudo /sbin/iptables -A INPUT -s 10.101.85.138 -j ACCEPT
sudo /sbin/iptables -A INPUT -s 10.101.85.18 -j ACCEPT
sudo /sbin/iptables -A INPUT -s 10.101.148.1 -j ACCEPT
sudo /sbin/iptables -A INPUT -s 10.101.85.137 -j ACCEPT

#Permite enviar comunicação para as maquinas descritas em baixo
sudo /sbin/iptables -A OUTPUT -d 10.121.52.14 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d 10.121.52.15 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d 10.121.52.16 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d 10.121.72.23 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d 10.101.85.138 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d 10.101.85.18 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d 10.101.148.1 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d 10.101.85.137 -j ACCEPT

# Permitir ping apenas do IP da máquina gcc
sudo iptables -A INPUT -p icmp --icmp-type 8 -s 10.0.2.15 -j ACCEPT
sudo iptables -A OUTPUT -p icmp --icmp-type 0 -j ACCEPT

# Permitir conexões SSH apenas do IP da máquina gcc
sudo iptables -A INPUT -p tcp --dport 22 -s 10.0.2.15 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Permitir conexões de clientes para o servidor myCloud
sudo iptables -A INPUT -p tcp --dport 23456 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 23456 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Permitir ping para a sub-rede local com máscara 255.255.254.0
sudo iptables -A INPUT -p icmp --icmp-type 8 -d 10.0.2.0/23 -j ACCEPT
sudo iptables -A OUTPUT -p icmp --icmp-type 0 -j ACCEPT

# Permitir tráfego relacionado com conexões estabelecidas
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT