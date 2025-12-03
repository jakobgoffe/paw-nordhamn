# PAW-Nordhamn  
Privileged Access Workstation (PAW) för OT-säkerhetscase.

---

## 📌 Syfte  
Detta projekt skapar en hårdgjord, isolerad och säker administrativ arbetsstation  
för OT-miljöer – inspirerad av Microsoft PAW-principer, Zero Trust och OT-best practice.

---

# 1️⃣ Grundinstallation (Debian 13)

### Steg:
1. Installera Debian 13 Minimal (Netinst).
2. Välj:  
   - Swedish keyboard  
   - UK locale (rekommenderat)  
3. Skapa en vanlig användare (ej root).  
4. Aktivera full disk encryption (LUKS).  

---

# 2️⃣ Rensa onödiga paket
Systemet hålls så litet som möjligt för att minimera attackytan.

```bash
sudo apt remove -y --purge \
    games-* \
    libreoffice-* \
    thunderbird \
    popularity-contest \
    transmission-* \
    gnome-games
sudo apt autoremove -y
sudo apt autoclean
```

---

# 3️⃣ SSH-härdning

### Installerar & aktiverar SSH:
```bash
sudo systemctl enable ssh
sudo systemctl start ssh
sudo nano /etc/ssh/sshd_config
```

### Ändra följande i `sshd_config`:
```
PasswordAuthentication no
PermitRootLogin no
MaxAuthTries 3
```

Spara med **CTRL+O**, avsluta med **CTRL+X**.

Starta om SSH:
```bash
sudo systemctl restart ssh
```

---

# 4️⃣ Full diskkryptering (LUKS)  
Debian-installationen använder redan LUKS när du valde “Guided – encrypted LVM”.  
Det skyddar hela systemet om någon får tag i .vdi-filen.

Ingen extra manuell åtgärd krävs här.

---

# 5️⃣ Installera nödvändiga verktyg

```bash
sudo apt update
sudo apt install -y ufw vim git unzip zip openssh-client \
    pulseaudio pavucontrol synaptic firmware-linux seahorse \
    openssl powertop
```

---

# 6️⃣ Aktivera UFW-brandvägg

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
sudo ufw status verbose
```

---

# 7️⃣ Systemskydd: Lynis, Fail2ban & AppArmor

Detta steg aktiverar systemhärdning, skydd mot brute-force på lokala inloggningar och kör obligatoriska säkerhetsprofiler för processer.

✔ Detta ger dig:

Lynis → säkerhetsrevision av PAW

Fail2ban → blockerar brute force mot sudo, TTY-inloggning och PAM

AppArmor → låser appar i sandlådor (Mandatory Access Control)

Enforced security profiles för systemtjänster

```bash
sudo apt install -y lynis fail2ban apparmor-utils apparmor-profiles apparmor-profiles-extra
sudo aa-enforce /etc/apparmor.d/*
sudo systemctl enable apparmor
sudo systemctl start apparmor
sudo apparmor_status

sudo systemctl enable fail2ban
sudo systemctl start fail2ban
sudo systemctl status fail2ban

````
Lynis säkerhetsrevision

```bash
sudo lynis audit system

```

---

# 8️⃣ Skydda sudo & lokala konton 
låser privilegier, stoppar ”sudo-spam”, kräver lösenord varje gång (MFA-liknande beteende), samt låser root-kontot helt.

```bash
sudo passwd -l root
sudo nano /etc/sudoers.d/00-paw-timeout
Defaults timestamp_timeout=0

```
Kontrollera sudoers-filen: 

```bash
sudo visudo
```

Kontrollera/ändra till:

```bash
Defaults    env_reset
Defaults    mail_badpass
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

root        ALL=(ALL:ALL) ALL
paw_nordhamn ALL=(ALL:ALL) ALL

```

---

# 9️⃣ Kernel-härdning (sysctl)
Kernel-härdning skyddar systemet mot spoofing, redirect-attacker, IP forwarding, syn-floods, dåliga ICMP-paket, samt aktiverar ASLR.
Detta är ett viktigt PAW-skydd eftersom PAW ska vara singel-purpose, isolerad och inte routa trafik eller agera gateway.

```bash
sudo nano /etc/sysctl.d/99-paw-hardening.conf
```

klistra in följande: 
```bash
# --- PAW Kernel Hardening ---

# Disable IP Forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Stoppa packet redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Stoppa ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Slå på reverse-path filtering (skydd mot spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable Kernel ASLR
kernel.randomize_va_space = 2

# Skydda mot syn-flood
net.ipv4.tcp_syncookies = 1

# Logga suspekt trafik
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 (valfritt — rekommenderas för extrem PAW-härdning)
net.ipv6.conf.all.disable_ipv6 = 1

```
Spara och stäng (ctrl+O -> enter, ctrl+X) Ladda sedan in reglerna: 

```bash
sudo sysctl --system
```

---

#  🔟 USB-restriktioner (USBGuard)
USBGuard blockerar ALLA USB-enheter som standard.
Endast enheter du själv tillåter får användas.

```bash
sudo apt update
sudo apt install -y usbguard
```

Generera policy baserad på nuvarande hårdvara
Det här tar en ögonblicksbild av alla USB-enheter som just nu är inkopplade
```
```bash
sudo usbguard generate-policy > ~/usbguard-policy.conf
sudo mv ~/usbguard-policy.conf /etc/usbguard/rules.conf
```

Aktivera & starta tjänsten

```bash

sudo systemctl enable usbguard
sudo systemctl start usbguard
sudo systemctl status usbguard

sudo usbguard list-devices
```

Lås ner allt som INTE är godkänt

```bash
sudo usbguard set-parameter ApplyPolicyOnInsert=true
sudo usbguard set-parameter ImplicitPolicyTarget=block
```

---

#  1️⃣1️⃣ Skapa strukturerade mappar för nycklar, projekt och säker filer

```bash
mkdir -p ~/Documents/Keys
mkdir -p ~/Documents/SecureFiles
mkdir -p ~/Documents/Projects
```

---

# 1️⃣2️⃣ Energioptimering (valfritt)
```bash
sudo powertop --auto-tune
```

---

# 1️⃣2️⃣ Snapshot i VirtualBox  
När PAW är konfigurerad:

**VirtualBox → Machine → Take Snapshot → “PAW-Clean-Base”**

Detta gör att du kan återställa en ren säker miljö när som helst.

---

# 1️⃣3️⃣ Vidare härdningsalternativ (valfritt)
För avancerad härdning rekommenderas:

✔ TPM-stöd & Secure Boot

✔ Wayland sandboxing (Flatpak portals)

✔ Avstängning av Bluetooth / WiFi om PAW ej behöver det

✔ Firejail för isolerade verktyg

✔ AppArmor-profiler för specifika program

✔ Hardened_malloc (särskilt säkert minnesbibliotek)

✔ Säkra syslog → remote log server

✔ Whitelisting av systemd‐tjänster

✔ Bootloader-lösenord (GRUB-härdning)

✔ Autoupdates + unattended-upgrades

---

# ✔️ Status: PAW-Nordhamn klar  
Du har nu en säker, hårdgjord, spårbar administrativ arbetsstation som är lämplig för  
labbmiljöer, säker drift, OT-demo och simulerad incidenthantering.

Systemet följer principer från:

CIS Benchmarks

NIST 800-53

Microsoft PAW Guidance

Zero Trust Architecture

