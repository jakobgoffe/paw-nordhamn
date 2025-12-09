# PAW-Nordhamn  
Privileged Access Workstation (PAW) för OT-säkerhetscase.
FAS 1: PAW
FAS 2: OT-komponent på RPi

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

# 1️⃣4️⃣ Fas 2: UPS Implementation & Hardening (OT-Segment)
I denna fas simuleras en kritisk OT-komponent (Uninterruptible Power Supply) med hjälp av en Raspberry Pi.

Installation & Nätverk
- OS: Raspberry Pi OS Lite (Headless)
- IP: 192.168.68.130 (Statisk)

Säkerhetshärdning med nftables (Strict Firewall)
Implementering av "Default Deny" med strikt käll-låsning (Source Hardening). Enheten tillåter endast trafik från den betrodda PAW-enheten.

```bash
sudo nano /etc/nftables.conf
```

klistra in: 
```bash
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif "lo" accept
        ip protocol icmp accept
        # TILLÅT ENDAST FRÅN PAW:
        ip saddr 192.168.68.132 tcp dport 22 accept
        ip saddr 192.168.68.132 udp dport 514 accept
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output { type filter hook output priority 0; policy accept; }
}
```

---

# 1️⃣5️⃣ Centraliserad Loggning (Syslog Setup)

Raspberry PI konfigurerades som loggserver för att ta emot händelser från PAW.

På mottagaren (UPS): Aktivera UDP-mottagning i 
```bash
sudo nano /etc/rsyslog.conf:

# Uncommented:
module(load="imudp")
input(type="imudp" port="514")
```

På sändaren (PAW): Vidarebefordra alla loggar till UPS:
```bash
# Lade till i slutet av /etc/rsyslog.conf:
*.* @192.168.68.130:514
```

Verifiering: Trafiken bekräftades genom att "avlyssna" nätverkskortet:
```bash
sudo tcpdump -i any udp port 514
# Resultat: Paket bekräftades anlända från 192.168.68.132
```
Verifiering Applikationsnivå (Log Verification):
```bash
# På PAW (Sänd testmeddelande):
logger "Test från PAW till UPS"

# På UPS (Läs loggfil):
tail -f /var/log/syslog
# Resultat: "Dec 9 10:00:00 nordhamn-paw user: Test från PAW till UPS"
```

---

#1️⃣6️⃣ OT-Simulering (Python Script)
För att generera realistisk telemetri och testa loggkedjan skapades ett skript som simulerar UPS-status (spänning och batteri) på PI och skickar detta som syslog-meddelanden.

öppna fil:
```bash
nano ups_simulation.py
```

klistra in:
```python
import syslog
import time
import random

# Konfigurera logg mot lokal syslog (som sedan vidarebefordras/sparas)
syslog.openlog("Nordhamn-UPS", syslog.LOG_PID, syslog.LOG_USER)

print("UPS Simulation startad...")

while True:
    # Simulera spänningsvariation
    voltage = random.randint(228, 235)
    
    # 10% risk för strömavbrott
    status_check = random.randint(1, 10)
    
    if status_check == 1:
        msg = f"WARNING: Power Grid Lost! Running on Battery. Voltage: {voltage}V"
        syslog.syslog(syslog.LOG_WARNING, msg)
        print(f"Skickat larm: {msg}")
    else:
        msg = f"INFO: Operating Normal. Grid OK. Voltage: {voltage}V"
        syslog.syslog(syslog.LOG_INFO, msg)
        print(f"Skickat status: {msg}")

    time.sleep(5)
```
### Verifiering av OT-data
För att bekräfta att simuleringen fungerar och att loggkedjan är intakt:

1. **Starta simuleringen:**
   ```bash
   python3 ups_simulation.py
   ```
2. **Övervaka loggflödet**
     ```bash
   tail -f /var/log/syslog | grep "Nordhamn-UPS"
      ```
---

# 1️⃣7️⃣ Slutsats & Nästa Steg
Projektet har framgångsrikt etablerat en säker OT-arkitektur enligt **IEC 62443**-principer.

**Uppnådda mål i FAS 2:**
✅ **Segmentering:** Dedikerad hårdvara för OT-funktion (UPS).
✅ **Härdning:** Minimal OS-installation och strikt "Default Deny"-brandvägg.
✅ **Synlighet:** Centraliserad loggning av både systemhändelser och processdata.

**Framtida utveckling:**
- Implementera logganalys (SIEM) för att automatiskt larma på "Power Grid Lost".
- Konfigurera TLS-kryptering för Syslog-trafiken.

---

# ✔️ Status: PAW-Nordhamn klar  
Du har nu en säker, hårdgjord, spårbar administrativ arbetsstation som är lämplig för  
labbmiljöer, säker drift, OT-demo och simulerad incidenthantering.

Systemet följer principer från:

CIS Benchmarks

NIST 800-53

Microsoft PAW Guidance

Zero Trust Architecture

