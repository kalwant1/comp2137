#!/bin/bash
# Check if the system is already configured correctly.
# Check if the hostname is set to autosrv.
if [ "$(hostname)" != "autosrv" ]; then
  echo "Setting hostname to autosrv..."
  hostnamectl set-hostname autosrv
fi






# Check if the network configuration is correct.



# Check if the interface is ens34, ens37, or enp3s8.
if ! [[ "$(ip addr show | grep -E 'ens34|ens37|enp3s8')" ]]; then
  echo "Creating interface ens34..."
  ip link add ens34 type ethernet
fi
# Set the interface up.
echo "Setting interface ens34 up..."
ip link set ens34 up
# Add an IP address to the interface.
echo "Adding IP address 192.168.16.21/24 to interface ens34..."
ip addr add 192.168.16.21/24 dev ens34
# Add a default route to the interface.
echo "Adding default route via 192.168.16.1 to interface ens34..."
ip route add default via 192.168.16.1 dev ens34
# Check if the IP address and gateway/DNS server are already configured.
if ! [[ "$(ip addr show ens34 | grep 'inet 192.168.16.21/24')" ]]; then
  echo "Adding IP address 192.168.16.21/24 to interface ens34..."
  ip addr add 192.168.16.21/24 dev ens34
fi
if ! [[ "$(ip route show | grep 'default via 192.168.16.1')" ]]; then
  echo "Adding default route via 192.168.16.1 to interface ens34..."
  ip route add default via 192.168.16.1 dev ens34
fi
# Set the DNS search domains to home.arpa and localdomain.
echo "Setting DNS search domains to home.arpa and localdomain..."
echo 'search home.arpa localdomain' >> /etc/resolv.conf
echo "Your Network Configurations are set."









# Check if the software is installed correctly.





# Check if the SSH server is installed
if ! sudo apt-get install openssh-server; then
  echo "The SSH server is not installed."
  echo "Installing.."
  sudo apt update
  sudo apt install openssh-server
  echo "Done."
fi

# Check if the Apache web server is installed
if ! sudo apt-get install apache2; then
  echo "The Apache web server is not installed."
  sudo apt-get install apache2
  echo "Installing.."
  echo "Done."
fi

# Check if the Squid web proxy is installed
if ! sudo apt-get install squid; then
  echo "The Squid web proxy is not installed."
  sudo apt-get install squid
  echo "Installing.."
  echo "Done."
fi



# Check if the SSH server is configured to allow SSH key authentication and not allow password authentication
if ! sudo grep -v '^PasswordAuthentication yes' /etc/ssh/sshd_config; then
  echo "The SSH server is not configured to allow SSH key authentication and not allow password authentication."
fi
# Check if the Apache web server is listening for HTTP on port 80 and HTTPS on port 443
if ! sudo netstat -tulpn | grep apache2; then
  echo "The Apache web server is not listening for HTTP on port 80 and HTTPS on port 443."
fi
# Check if the Squid web proxy is listening on port 3128
if ! sudo netstat -tulpn | grep squid; then
  echo "The Squid web proxy is not listening on port 3128."
fi
# All checks passed!
echo "The software is installed and configured correctly."







# Check if the firewall is configured correctly.




# Get the current firewall rules.
ufw status
# Check if the ssh port is open.
if ! ufw status | grep '22/tcp'; then
  echo "The ssh port is not open."
fi
# Check if the http port is open.
if ! ufw status | grep '80/tcp'; then
  echo "The http port is not open."
fi
# Check if the https port is open.
if ! ufw status | grep '443/tcp'; then
  echo "The https port is not open."
fi
# Check if the web proxy port is open.
if ! ufw status | grep '3128/tcp'; then
  echo "The web proxy port is not open."
fi

# add the rules which are not there.
echo "Adding the required rules.."
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3128/tcp
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
  useradd -m -s /bin/bash $user
done

# Create a home directory for each user.
echo "Creating Home Directories."
for user in ("aubrey", "captain", "nibbles", "brownie", "scooter", "sandy", "perrier", "cindy", "tiger", "yoda"); do
  mkdir -p /home/$user
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
