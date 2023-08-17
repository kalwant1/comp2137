#!/bin/bash

EXPECTED_HOSTNAME="autosrv"

# Get the current hostname
current_hostname=$(hostname)

# Check if the hostname matches the expected value
if [ "$current_hostname" = "$EXPECTED_HOSTNAME" ]; then
	    echo "Hostname is already set to '$EXPECTED_HOSTNAME'"
    else
	        # Update the hostname
		    echo "Updating hostname to '$EXPECTED_HOSTNAME'..."
		        sudo hostnamectl set-hostname "$EXPECTED_HOSTNAME"
			    echo "Hostname updated successfully."
fi

EXPECTED_ADDRESS="192.168.16.21/24"
EXPECTED_GATEWAY="192.168.16.1"
EXPECTED_DNS_SERVER="192.168.16.1"
EXPECTED_DNS_SEARCH="home.arpa localdomain"
INTERFACE="enp0s8"

# Get the current configuration of the interface
current_address=$(ip addr show dev "$INTERFACE" | awk '/inet / {print $2}')
current_gateway=$(ip route show default | awk '/default/ {print $3}')
current_dns_server=$(cat /etc/resolv.conf | awk '/nameserver/ {print $2}')
current_dns_search=$(cat /etc/resolv.conf | awk '/search/ {$1=""; print $0}' | tr -s ' ')

# Compare current configuration with expected values
if [ "$current_address" = "$EXPECTED_ADDRESS" ] && [ "$current_gateway" = "$EXPECTED_GATEWAY" ] && [ "$current_dns_server" = "$EXPECTED_DNS_SERVER" ] && [ "$current_dns_search" = "$EXPECTED_DNS_SEARCH" ]; then
    echo "Network configuration is already set correctly."
else
	    # Update the network configuration
	        echo "Updating network configuration..."
		    sudo ip addr flush dev "$INTERFACE"
		        sudo ip addr add "$EXPECTED_ADDRESS" dev "$INTERFACE"
			    sudo ip route add default via "$EXPECTED_GATEWAY" dev "$INTERFACE"
			        echo "nameserver $EXPECTED_DNS_SERVER" | sudo tee /etc/resolv.conf > /dev/null
				    echo "search $EXPECTED_DNS_SEARCH" | sudo tee -a /etc/resolv.conf > /dev/null
				        echo "Network configuration updated successfully."
fi


sudo apt-get install -y ssh apache2 squid ufw
# Check and configure SSH settings
if ! grep -q "PasswordAuthentication no" /etc/ssh/sshd_config; then
	    echo "Configuring SSH..."
	        sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
		    sudo systemctl restart ssh
		        echo "SSH configured."
		else
			    echo "SSH already configured."
fi

# Check and configure Apache2 for HTTP and HTTPS
if ! grep -q "Listen 80" /etc/apache2/ports.conf; then
	    echo "Configuring Apache2 for HTTP..."
	        sudo sed -i 's/Listen 80/Listen 80\nListen 443/' /etc/apache2/ports.conf
		    sudo systemctl restart apache2
		        echo "Apache2 configured for HTTP and HTTPS."
		else
			    echo "Apache2 already configured."
fi

# Check and configure Squid for port 3128
if ! grep -q "http_port 3128" /etc/squid/squid.conf; then
	    echo "Configuring Squid for port 3128..."
	        sudo sed -i 's/http_port .*/http_port 3128/' /etc/squid/squid.conf
		    sudo systemctl restart squid
		        echo "Squid configured for port 3128."
		else
			    echo "Squid already configured."
fi

echo "Configuration check and update complete."
#Allow SSH on port 22
if ! sudo ufw status | grep -q "22/tcp"; then
	    echo "Allowing SSH on port 22..."
	        sudo ufw allow 22/tcp
		    echo "SSH allowed on port 22."
fi

# Allow HTTP on port 80
if ! sudo ufw status | grep -q "80/tcp"; then
	    echo "Allowing HTTP on port 80..."
	        sudo ufw allow 80/tcp
		    echo "HTTP allowed on port 80."
fi

# Allow HTTPS on port 443
if ! sudo ufw status | grep -q "443/tcp"; then
	    echo "Allowing HTTPS on port 443..."
	        sudo ufw allow 443/tcp
		    echo "HTTPS allowed on port 443."
fi

# Allow web proxy on port 3128
if ! sudo ufw status | grep -q "3128/tcp"; then
	    echo "Allowing web proxy on port 3128..."
	        sudo ufw allow 3128/tcp
		    echo "Web proxy allowed on port 3128."
fi

# Enable UFW
if ! sudo ufw status | grep -q "Status: active"; then
	    echo "Enabling UFW..."
	        sudo ufw --force enable
		    echo "UFW enabled."
fi

echo "Firewall configuration complete."

# List of user configurations
USERS=("dennis:sudo:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5kndS4HmgTrKBT8SKzhK4rhGkEVGlCI student@generic-vm"
    "aubrey::"
    "captain::"
    "snibbles::"
    "brownie::"
    "scooter::"
    "sandy::"
    "perrier::"
    "cindy::"
    "tiger::"
    "yoda::"
)

# Create users and configure SSH keys
for user_config in "${USERS[@]}"; do
    IFS=":" read -r username sudo_key ssh_keys <<< "$user_config"
    
    # Check if the user already exists
    if id "$username" &>/dev/null; then
        echo "User '$username' already exists."
    else
        echo "Creating user '$username'..."
        sudo adduser --disabled-password --gecos "" "$username"
        echo "$username ALL=(ALL) NOPASSWD:ALL" | sudo tee "/etc/sudoers.d/$username" > /dev/null
        echo "User '$username' created."
    fi
    
    # Configure SSH keys for the user
    if [ -n "$ssh_keys" ]; then
        home_dir="/home/$username"
        ssh_dir="$home_dir/.ssh"
        authorized_keys="$ssh_dir/authorized_keys"
        
        sudo mkdir -p "$ssh_dir"
        echo "$ssh_keys" | sudo tee -a "$authorized_keys" > /dev/null
        sudo chown -R "$username:$username" "$ssh_dir"
        echo "SSH keys configured for user '$username'."
    fi
done

echo "User account creation and configuration complete."

