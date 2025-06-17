
To create a **bootable SD card with Kubernetes installed**, you generally want to set up a small single-board computer (like a Raspberry Pi) that boots from the SD card and runs Kubernetes (often as a single-node cluster). Here’s a step-by-step guide for the most common scenario: **booting a Raspberry Pi with Kubernetes using Raspberry Pi OS (or Ubuntu) and kubeadm**.

---

## 1. Prepare the SD Card

**a. Download an OS Image:**  
- Download Raspberry Pi OS Lite or Ubuntu Server for Raspberry Pi.

**b. Flash the Image:**  
- Use [Raspberry Pi Imager](https://www.raspberrypi.com/software/) or [balenaEtcher](https://www.balena.io/etcher/) to write the image to the SD card.

**c. (Optional) Enable SSH and Wi-Fi:**  
- For Raspberry Pi OS, create an empty `ssh` file in the `/boot` partition of the SD card to enable SSH on boot.
- For Wi-Fi, create a `wpa_supplicant.conf` file in `/boot` with your network credentials.

---

## 2. Boot and Initial Setup

- Insert the SD card into your Raspberry Pi and power it on.
- SSH into the Pi or connect a monitor and keyboard.

---

## 3. Install Kubernetes (Single-Node Cluster)

**a. Update the System:**
```sh
sudo apt-get update && sudo apt-get upgrade -y
```

**b. Install Docker:**
```sh
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```
Log out and back in to apply Docker group changes.

**c. Install kubeadm, kubelet, kubectl:**
```sh
sudo apt-get update && sudo apt-get install -y apt-transport-https ca-certificates curl
sudo curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
```

**d. Disable Swap:**
```sh
sudo dphys-swapfile swapoff
sudo dphys-swapfile uninstall
sudo systemctl disable dphys-swapfile
sudo swapoff -a
```

**e. Initialize Kubernetes Cluster:**
```sh
sudo kubeadm init --pod-network-cidr=10.244.0.0/16
```
- Follow the kubeadm output to set up your kubeconfig for `kubectl`:
  ```sh
  mkdir -p $HOME/.kube
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config
  ```

**f. Install a Pod Network (e.g., Flannel):**
```sh
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
```

**g. (Optional) Allow Scheduling on the Master Node:**
```sh
kubectl taint nodes --all node-role.kubernetes.io/control-plane-
```

---

## 4. Verify the Installation

```sh
kubectl get nodes
kubectl get pods --all-namespaces
```

---

## 5. Make Image Portable (Optional Advanced Step)

To **re-use this SD card** on other Pis, consider making a backup image of the SD card after setup using `dd` or Raspberry Pi Imager.

---

### Notes

- This setup is for **single-node, non-production use** (like testing, learning, or development).
- For multi-node clusters or production, network, security, and stateful storage require more configuration.
- You can use similar steps for other ARM-based boards (RockPi, OrangePi, etc.) with appropriate OS images.

