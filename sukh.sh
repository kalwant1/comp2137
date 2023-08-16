#!/bin/bash
# So to make this script, i will make different functions which will execute the commands to change the configurations to required ones.
# Also i will make some condition commands which will check the old configurations and then work accordingly.

# first function is to set host name to autosrv.
set_hostname() {
    if [ "$(hostname)" != "autosrv" ]; then
        local HOSTNAME="autosrv"
        hostnamectl set-hostname $HOSTNAME
    fi    
}
# now to set up network interface, i will first find the required one.
# then i will change its configurations.
setup_network() {
    local IP_ADDR="192.168.16.21/24"
    local GATEWAY="192.168.16.1"
    local DNS_DOMAINS="home.arpa localdomain"
    local INTERFACE= "$(ip route | awk '$1 == "default" {default_route = $3} $3 != default_route {print $3}')"

    ip addr add $IP_ADDR dev $INTERFACE
    ip route add default via $GATEWAY dev $INTERFACE
    echo "search $DNS_DOMAINS" >> /etc/resolv.conf
    ip link set $INTERFACE up
}
# now i will not check for the softwares because the following commands will automatically install if they are not.
install_software() {
    apt-get update
    apt-get install -y openssh-server apache2 squid
}
# the following commands will configure the ssh.
configure_ssh() {
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
    systemctl restart sshd
}
# now i will give the following firewall commands which will automatically correct the required configurations. This part does not need a condition statement because if the rule is not present, it will automatically be set up.
configure_firewall() {
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 3128/tcp
}
# now when all of the commands are set up, i will make final function, which will be the main body of the script and which will execute every different part made till now.
main() {
    set_hostname
    setup_network
    install_software
    configure_ssh
    configure_firewall
}
# here is the command to run that main function.
main "$@"
# now when other system configurations have been set, the last part to create users will be done.
# first of all i will create user array
USERS=("dennis" "aubrey" "captain" "nibbles" "brownie" "scooter" "sandy" "perrier" "cindy" "tiger" "yoda")
# now i will make a for loop which will run for all the users.
for USER in "${USERS[@]}"; do
    # this command will add the new user.
    useradd -m -s /bin/bash $USER
    # now i will generate ssh keys for the user.
    ssh-keygen -t rsa -f /home/$USER/.ssh/id_rsa -q -N ""
    ssh-keygen -t ed25519 -f /home/$USER/.ssh/id_ed25519 -q -N ""
    cat /home/$USER/.ssh/id_rsa.pub >> /home/$USER/.ssh/authorized_keys
    cat /home/$USER/.ssh/id_ed25519.pub >> /home/$USER/.ssh/authorized_keys
    # now i will change the permissions.
    chmod 700 /home/$USER
    chmod 600 /home/$USER/.ssh/id_rsa
    chmod 600 /home/$USER/.ssh/id_ed25519
    chmod 644 /home/$USER/.ssh/authorized_keys
done
# now i will Add sudo access and extra public key to the 'dennis' user
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5kndS4HmgTrKBT8SKzhK4rhGkEVGlCI student@generic-vm' >> /home/dennis/.ssh/authorized_keys
usermod -aG sudo dennis
#
