#!/bin/bash

# Check if the hostname is set to autosrv.
if [ "$(hostname)" != "autosrv" ]; then
  echo "Setting hostname to autosrv..."
  hostnamectl set-hostname autosrv
else
  echo "Hostname is already set. "
fi


# Check if the network configuration is correct.


local interface="ens34"
local ip_address="192.168.16.21/24"
local gateway="192.168.16.1"

    # Check if interface exists
if ! ip link show $interface &> /dev/null; then
    echo "Interface $interface not found."
fi

    # Check if IP address is set
if ! ip addr show $interface | grep -q "$ip_address"; then
    echo "Setting IP address $ip_address on $interface..."
    ip addr add $ip_address dev $interface
fi

    # Check if default gateway is set
if ! ip route | grep -q "default via $gateway"; then
    echo "Setting default gateway $gateway via $interface..."
    ip route add default via $gateway dev $interface
fi


# Set the DNS search domains to home.arpa and localdomain.
echo "Setting DNS search domains to home.arpa and localdomain..."
echo 'search home.arpa localdomain' >> /etc/resolv.conf
echo "Your Network Configurations are set."
echo "Network Settings are up to date"








# to check and set software configuration
apt-get update
apt-get install -y openssh-server apache2 squid
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
echo "Software configurations are up to date"



echo "The software is installed and configured correctly."







# Check if the firewall is configured correctly.




# Get the current firewall rules.
ufw status
# Check if the ssh port is open.
if ! ufw status | grep '22/tcp'; then
  echo "The ssh port is not open."
  ufw allow 22/tcp
fi
# Check if the http port is open.
if ! ufw status | grep '80/tcp'; then
  echo "The http port is not open."
  ufw allow 80/tcp
fi
# Check if the https port is open.
if ! ufw status | grep '443/tcp'; then
  echo "The https port is not open."
  ufw allow 443/tcp
fi
# Check if the web proxy port is open.
if ! ufw status | grep '3128/tcp'; then
  echo "The web proxy port is not open."
  ufw allow 3128/tcp
fi

# Reload the firewall rules.
echo "Reloading the Firewall.."
ufw reload
echo "Firewall Configured Successfully."













# Check if the user accounts are created correctly.



# for dennis 
if [ $(grep dennis /etc/passwd) ]; then
  echo "The user exists."
else
  echo "The user does not exist."
  # Create a new user account.
  echo "Creating User 'dennis'"
  useradd -m -s /bin/bash dennis
  # Create a home directory for the new user.
  mkdir -p /home/dennis
  # Generate an SSH key for the new user.
  echo "Generating and adding SSH Keys.."
  ssh-keygen -t rsa -f /home/dennis/.ssh/id_rsa -N ""
  ssh-keygen -t ed25519 -f /home/dennis/.ssh/id_ed25519 -N ""
  # Add the public SSH keys to the new user's authorized_keys file.
  cat /home/dennis/.ssh/id_rsa.pub >> /home/dennis/.ssh/authorized_keys
  cat /home/dennis/.ssh/id_ed25519.pub >> /home/dennis/.ssh/authorized_keys
  # now add the given ssh key
  ssh-keygen -f /home/dennis/.ssh/authorized_keys -t ed25519 -N "" -e < ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5kndS4HmgTrKBT8SKzhK4rhGkEVGlCI student@generic-vm

  # Change the permissions on the new user's home directory and SSH keys.
  echo "Setting Permissions.."
  chmod 700 /home/dennis
  chmod 600 /home/dennis/.ssh
  chmod 600 /home/dennis/.ssh/id_rsa
  chmod 600 /home/dennis/.ssh/id_ed25519
  chmod 644 /home/dennis/.ssh/authorized_keys
  # setting sudo permissions for dennis.
  sudo usermod -aG sudo username
fi





# now all other users.




# Create a new user account for each user.
echo "Adding Users."
for user in ("aubrey", "captain", "nibbles", "brownie", "scooter", "sandy", "perrier", "cindy", "tiger", "yoda"); do
  id -u $user >/dev/null 2>&1
  if [ "$?" == "0" ]; then
    echo "user $user already exist."
  else
    echo "user $user doesn't exist."
    useradd -m -s /bin/bash $user
  fi
    
done

# Generate an SSH key for each user.
echo " Generating SSH-Keys."
for user in ("aubrey", "captain", "nibbles", "brownie", "scooter", "sandy", "perrier", "cindy", "tiger", "yoda"); do
  ssh-keygen -t rsa -f /home/$user/.ssh/id_rsa -N ""
  ssh-keygen -t ed25519 -f /home/$user/.ssh/id_ed25519 -N ""
done

# Add the public SSH keys to each user's authorized_keys file.
for user in ("aubrey", "captain", "nibbles", "brownie", "scooter", "sandy", "perrier", "cindy", "tiger", "yoda"); do
  cat /home/$user/.ssh/id_rsa.pub >> /home/$user/.ssh/authorized_keys
  cat /home/$user/.ssh/id_ed25519.pub >> /home/$user/.ssh/authorized_keys
done

# Change the permissions on each user's home directory and SSH keys.
echo "Giving Permissions."
for user in ("aubrey", "captain", "nibbles", "brownie", "scooter", "sandy", "perrier", "cindy", "tiger", "yoda"); do
  chmod 700 /home/$user
  chmod 600 /home/$user/.ssh
  chmod 600 /home/$user/.ssh/id_rsa
  chmod 600 /home/$user/.ssh/id_ed25519
  chmod 644 /home/$user/.ssh/authorized_keys
done
echo "Users Created Successfully."
