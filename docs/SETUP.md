# ABHED-v2 setup guide: from an empty computer to a running post-quantum DNSSEC lab

This guide assumes **nothing is installed** on your computer. Follow the part for your
operating system, then continue with the common steps. Every command is meant to be copied
exactly.

Developed by Rajdeep Das, Research Fellow, IEM-UEM, Kolkata, India.

---

## Contents

0. [What you need](#0-what-you-need)
1. [Get a Linux system](#1-get-a-linux-system) (Windows, macOS, Linux)
2. [Install the build tools](#2-install-the-build-tools)
3. [Download ABHED-v2](#3-download-abhed-v2)
4. [Build everything](#4-build-everything)
5. [Run the tests](#5-run-the-tests)
6. [Use the lab: your first post-quantum DNSSEC queries](#6-use-the-lab-your-first-post-quantum-dnssec-queries)
7. [Try the other algorithms and profiles](#7-try-the-other-algorithms-and-profiles)
8. [Run the benchmarks](#8-run-the-benchmarks)
9. [Sign your own zone](#9-sign-your-own-zone)
10. [Containers with Podman (optional)](#10-containers-with-podman-optional)
11. [Update, clean up, uninstall](#11-update-clean-up-uninstall)
12. [Troubleshooting](#12-troubleshooting)

---

## 0. What you need

| Item | Minimum | Recommended |
|---|---|---|
| Computer | 64-bit (x86-64). ARM (Apple silicon, Raspberry Pi) should work but is not tested. | |
| Memory | 4 GB | 8 GB |
| Free disk | 5 GB | 10 GB |
| Internet | Needed once, for installing packages and downloading NSD, Unbound and liboqs | |
| Rights | Administrator (Windows/macOS) or `sudo` (Linux) | |
| Time | About 30 minutes the first time, most of it waiting | |

ABHED-v2 runs on **Linux**. It was built and tested on **Ubuntu 24.04 LTS**, and that is the
system this guide installs. On Windows and macOS you run Ubuntu 24.04 inside your computer
(section 1).

Why Linux and why administrator rights: the lab starts real DNS servers on the addresses
127.0.53.10, .20, .30 and .53, port 53. Port 53 is a privileged port, and only Linux treats
every 127.x.x.x address as local without extra setup.

The lab only listens on your own computer. Nothing is reachable from the network, and nothing
changes your computer's normal DNS settings.

---

## 1. Get a Linux system

Pick **one** of 1A, 1B or 1C.

### 1A. Windows 10 or 11: WSL2 (Windows Subsystem for Linux)

WSL2 runs a real Ubuntu inside Windows. Requires Windows 10 version 2004 or later, or Windows 11.

1. **Check that virtualisation is on.** Press `Ctrl+Shift+Esc` to open Task Manager, open the
   **Performance** tab, click **CPU**. "Virtualization: Enabled" must be shown. If it says
   Disabled, enable "Intel VT-x" / "AMD-V" / "SVM" in your computer's BIOS/UEFI settings
   (search the web for your laptop model plus "enable virtualization").
2. **Open PowerShell as administrator.** Press the Windows key, type `powershell`, right-click
   **Windows PowerShell**, choose **Run as administrator**, click **Yes**.
3. **Install WSL and Ubuntu 24.04:**
   ```powershell
   wsl --install -d Ubuntu-24.04
   ```
4. **Restart Windows** when it asks.
5. After the restart an Ubuntu window opens (if not, press the Windows key and open
   **Ubuntu 24.04**). It asks for a **new UNIX username** and **password**. Choose any; this is
   only for Ubuntu. You will type the password when a command uses `sudo`. Nothing is shown
   while you type a password; that is normal.
6. Check that it is WSL version 2. In PowerShell (normal, not administrator):
   ```powershell
   wsl -l -v
   ```
   The VERSION column must show **2**. If it shows 1: `wsl --set-version Ubuntu-24.04 2`.

From now on, type every command in the **Ubuntu** window, not in PowerShell.

> **Important for Windows users**
> - Keep the project inside Ubuntu's own home folder (`~`), **not** under `/mnt/c/...`.
>   Files on the Windows drive lose their Linux permissions and build very slowly.
> - Leave WSL networking at its default (NAT). The "mirrored" networking mode shares ports with
>   Windows and can block port 53.
> - To open the Ubuntu files from Windows Explorer, type `\\wsl$` in the address bar.

### 1B. macOS (Intel or Apple silicon): an Ubuntu virtual machine with Multipass

Multipass is Canonical's free tool for Ubuntu virtual machines.

1. Download the macOS installer from https://canonical.com/multipass/install and install it
   (double-click the `.pkg`, follow the steps, enter your Mac password when asked).
2. Open **Terminal** (Applications, Utilities, Terminal) and create the virtual machine:
   ```bash
   multipass launch 24.04 --name abhed --cpus 2 --memory 4G --disk 20G
   ```
3. Open a shell inside it:
   ```bash
   multipass shell abhed
   ```
   The prompt changes to `ubuntu@abhed`. Type every following command there.
   The `ubuntu` user can use `sudo` without a password.

Later: `multipass stop abhed` stops the machine, `multipass start abhed` and
`multipass shell abhed` continue. On Apple silicon the virtual machine is ARM (aarch64);
this works in principle but has not been tested.

### 1C. Linux

- **Ubuntu 24.04** (desktop, server or virtual machine): nothing to do, continue with section 2.
- **Ubuntu 22.04**: should work (not tested), but its Go is too old. In section 2, install Go with
  `sudo snap install go --classic` instead of `golang-go`.
- **Other distributions** (Debian, Fedora, Arch, ...): package names differ. Either install
  Ubuntu 24.04 in a virtual machine (for example with Multipass: `sudo snap install multipass`,
  then follow 1B from step 2), or install the equivalents of the section 2 packages and Go 1.22
  or newer yourself.

To check what you have: `cat /etc/os-release`.

---

## 2. Install the build tools

In the Ubuntu terminal:

```bash
sudo apt-get update
sudo apt-get install -y git ca-certificates build-essential cmake ninja-build \
    autoconf automake libtool flex bison pkg-config \
    libssl-dev libevent-dev libexpat1-dev libldns-dev \
    golang-go dnsutils
```

What these are, so you know what you installed:

| Package | Used for |
|---|---|
| `git`, `ca-certificates` | download the project, NSD, Unbound and liboqs |
| `build-essential`, `cmake`, `ninja-build` | C compiler and build systems |
| `autoconf`, `automake`, `libtool`, `flex`, `bison`, `pkg-config` | needed to build NSD and Unbound from source |
| `libssl-dev`, `libevent-dev`, `libexpat1-dev`, `libldns-dev` | libraries NSD, Unbound and the zone signer use |
| `golang-go` | Go compiler for the tools `abhedctl` and `abhed-bench` |
| `dnsutils` | `dig`, the command you use to query DNS |

Check:

```bash
gcc --version | head -1          # gcc ... 13.x
cmake --version | head -1        # cmake version 3.28 or newer
go version                       # go1.22 or newer
dig -v                           # DiG 9.18 ...
```

---

## 3. Download ABHED-v2

```bash
cd ~
git clone https://github.com/drajdeep/ABHED-v2-native.git
cd ABHED-v2-native
ls
```

You should see `deploy`, `docs`, `go`, `lib`, `patches`, `tools`, `README.md` and others.

No git? You can also download the ZIP from the GitHub page (green **Code** button,
**Download ZIP**), copy it into Ubuntu and unpack it with `unzip`. Everything below works the
same way.

Every following command is run **inside this folder** (`~/ABHED-v2-native`).

---

## 4. Build everything

```bash
sudo bash deploy/build.sh
```

This downloads the exact versions listed in `deploy/versions.env` (liboqs 0.16.0, NSD 4.15.4,
Unbound 1.26.2), applies the ABHED patches, builds everything and installs it into
**`/opt/abhed`**. Nothing else on your system is changed.

It takes about 3 to 10 minutes. The output looks like this (some compiler warnings in between
are normal):

```
==> fetching https://github.com/open-quantum-safe/liboqs @ 0.16.0
==> building liboqs 0.16.0 (ML-DSA-44 only)
==> building libabhed and tools
==> libabhed unit tests
1709 checks, 0 failures
==> fetching https://github.com/NLnetLabs/nsd @ NSD_4_15_4_REL
==> patching NSD NSD_4_15_4_REL
==> NSD installed: NSD version 4.15.4
==> fetching https://github.com/NLnetLabs/unbound @ release-1.26.2
==> patching Unbound release-1.26.2
==> Unbound installed: Version 1.26.2
==> building Go tools (vendored dependencies, offline)
==> done. Add /opt/abhed/bin and /opt/abhed/sbin to PATH.
```

The line **`1709 checks, 0 failures`** means the cryptographic library passed its own tests.

Options: `--prefix DIR` (install somewhere else), `--jobs N` (parallel compile jobs),
`--clean` (rebuild from scratch), `--sanitize` (debug build with address checks).

Source code of NSD, Unbound and liboqs is kept in `.build/` (about 360 MB) so a second build is
faster. The installed result in `/opt/abhed` is about 70 MB.

---

## 5. Run the tests

```bash
sudo bash deploy/test.sh
```

This starts the lab six times (MTL with three profiles, ML-DSA-44, a mixed KSK/ZSK setup and
classical ECDSA), queries it through the patched Unbound with `dig`, grows the zone, then
tampers with a record and checks that the resolver rejects it. It takes under a minute and
must end with:

```
60 passed, 0 failed
```

If you see this, the installation is complete and correct.

---

## 6. Use the lab: your first post-quantum DNSSEC queries

### 6.1 Open an administrator shell and set the path

The lab binds port 53, so work in a root shell for this section:

```bash
sudo -s
export PATH=/opt/abhed/bin:/opt/abhed/sbin:$PATH
```

The prompt ends with `#` now. Type `exit` when you are done to return to your normal user.

### 6.2 Create a lab

```bash
abhedctl init --dir /tmp/abhed-lab --mode mtl --hosts 1000 --profile abhed
```

This creates three zones, a root `.`, a top-level domain `lab.` and `iem.lab.` with 1,000
hosts, generates post-quantum keys, signs all zones with **ML-DSA-44 in Merkle Tree Ladder mode**
(algorithm number 244 in this lab), and writes configuration for NSD and Unbound. Output:

```
lab /tmp/abhed-lab: mode=mtl layout=csk order=hot-last hosts=1000 profile=abhed (signed in ...ms)
  DS iem.lab.  3600 IN DS ... 244 2 ...
  DS lab.      3600 IN DS ... 244 2 ...
  DS .         3600 IN DS ... 244 2 ...
trust anchor: /tmp/abhed-lab/etc/trust-anchor.ds
next: deploy/lab.sh up /tmp/abhed-lab
```

What is inside `/tmp/abhed-lab`:

| Folder | Content |
|---|---|
| `zones/` | unsigned (`.zone`) and signed (`.signed`) zone files |
| `keys/` | private and public keys (lab only, never reuse them) |
| `state/` | the MTL tree of each zone, needed to sign again later |
| `etc/` | NSD and Unbound configuration, root hints, trust anchor |
| `run/` | logs, process ids, control sockets |

### 6.3 Start it

```bash
bash deploy/lab.sh up /tmp/abhed-lab
bash deploy/lab.sh status /tmp/abhed-lab
```

```
==> lab up: resolver 127.0.53.53:53, authoritative 127.0.53.10 127.0.53.20 127.0.53.30
nsd-root running (pid ...)
nsd-lab  running (pid ...)
nsd-iem  running (pid ...)
unbound  running (pid ...)
```

You now have four real DNS servers on your computer:

| Address | Program | Role |
|---|---|---|
| 127.0.53.10 | NSD + ABHED patch | root zone `.` |
| 127.0.53.20 | NSD + ABHED patch | `lab.` |
| 127.0.53.30 | NSD + ABHED patch | `iem.lab.` |
| 127.0.53.53 | Unbound + ABHED patch | validating resolver: the one you query |

### 6.4 Ask for a name

```bash
dig @127.0.53.53 +dnssec host000042.iem.lab A
```

Look for three things in the output:

- `status: NOERROR`: the name exists.
- `flags: qr rd ra ad`: **`ad`** (Authenticated Data) means Unbound **verified the whole
  post-quantum chain** from the trust anchor through `.` and `lab.` down to this answer.
- An `RRSIG A 244 ...` line: the signature, algorithm 244 = ML-DSA-44-MTL.

The **first** answer is large (about 3 KB) and `dig` prints `;; Truncated, retrying in TCP mode.`
That is expected: the resolver did not have the zone's signed ladder yet, so the server sent a
**full** signature that carries it. Ask for another name:

```bash
dig @127.0.53.53 +dnssec host000044.iem.lab A | grep -E "flags:|MSG SIZE"
```

```
;; flags: qr rd ra ad; ...
;; MSG SIZE  rcvd: 288
```

288 bytes, validated, over UDP. The resolver now holds the ladder, tells the server so with the
SigTag option, and receives only a short Merkle proof instead of a 2,420-byte ML-DSA-44 signature.

### 6.5 Look inside the signatures

```bash
dig @127.0.53.53 +dnssec host000042.iem.lab A | abhed-sigdump
dig @127.0.53.53 +dnssec host000044.iem.lab A | abhed-sigdump
```

```
host000042.iem.lab. A alg 244: 2953-byte signature field, FULL (0x01): leaf 84, 10 siblings, ladder of 2012 leaves / 8 rungs, 2420-byte ML-DSA-44 signature
host000044.iem.lab. A alg 244: 186-byte signature field, COMPACT (0xF1): leaf 88, 10 siblings
```

(Numbers differ slightly on your machine because keys and randomisers are random.)

### 6.6 A name that does not exist

```bash
dig @127.0.53.53 +dnssec nosuchname.iem.lab A | grep -E "status|flags:|MSG SIZE"
```

`status: NXDOMAIN` with the `ad` flag: the resolver verified a signed proof that the name does
not exist. These are normally the largest DNSSEC answers; here about 480 bytes.

### 6.7 See what the servers sent

```bash
abhedctl status --dir /tmp/abhed-lab
```

The `nsd_iem` line counts `abhed.mtl.full`, `abhed.mtl.condensed`, `abhed.mtl.compact`
signatures, `num.truncated` (answers too big for UDP) and `abhed.tcp.queries`.

### 6.8 Grow the zone without a new ML-DSA signature per record

```bash
abhedctl grow --dir /tmp/abhed-lab --add 100
bash deploy/lab.sh reload /tmp/abhed-lab
dig @127.0.53.53 +dnssec host001050.iem.lab A | grep -E "status|flags:"
```

`grow` adds 100 hosts and re-signs: the output says `1 ML-DSA-44 signatures` for the whole
zone. `reload` makes NSD load the new zone and empties the resolver cache. Without the reload,
the resolver may answer NXDOMAIN for a new name for up to 5 minutes, from the proof of
non-existence it cached before (normal DNS behaviour).

### 6.9 Tamper with a record

```bash
sed -i -E 's/^(host000050\.iem\.lab\.[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+A[[:space:]]+).*/\1 10.99.99.99/' /tmp/abhed-lab/zones/iem.lab.signed
bash deploy/lab.sh reload /tmp/abhed-lab
dig @127.0.53.53 +dnssec host000050.iem.lab A | grep status     # SERVFAIL: forged data rejected
dig @127.0.53.53 +dnssec host000051.iem.lab A | grep status     # NOERROR: the rest still works
```

### 6.10 Stop the lab

```bash
bash deploy/lab.sh down /tmp/abhed-lab
exit
```

Other lab commands: `restart`, `restart-resolver` (empty resolver caches), `reload`, `status`,
`logs` (last lines of every server log).

---

## 7. Try the other algorithms and profiles

Create a new lab with different options, in the root shell (`sudo -s` and the `export PATH`
line from 6.1). Stop the running lab first, or use a different `--dir`.

| `--mode` | Keys |
|---|---|
| `ecdsa` | classical ECDSA P-256 (today's DNSSEC, not post-quantum) |
| `mldsa44` | plain ML-DSA-44 (algorithm 18) |
| `split` | ML-DSA-44 key-signing key, ECDSA zone-signing key |
| `mtl` | ML-DSA-44 in Merkle Tree Ladder mode (algorithm 244) |

| `--profile` (for `mtl`) | Behaviour |
|---|---|
| `base` | the base IETF draft: full signatures everywhere, every answer needs TCP |
| `sigtag` | plus the SigTag extension: short condensed signatures once the ladder is known |
| `abhed` | plus this project's additions: shorter compact signatures |

Example, plain ML-DSA-44, where every answer is too big for UDP:

```bash
abhedctl init --dir /tmp/lab-mldsa --mode mldsa44 --hosts 1000 --profile base
bash deploy/lab.sh up /tmp/lab-mldsa
dig @127.0.53.53 +dnssec host000042.iem.lab A | grep -E "Truncated|flags:|MSG SIZE"
bash deploy/lab.sh down /tmp/lab-mldsa
```

Only one lab can run at a time, because all labs use the same addresses.
All options: [`docs/USAGE.md`](USAGE.md).

---

## 8. Run the benchmarks

Quick run (about 3 minutes on 2 CPU cores):

```bash
sudo bash deploy/bench.sh --hosts 1000 --trials 1 --queries 100 --churn-hosts 200 --out results-quick
```

Full run, as used for the published results (much longer: 10,000-host zones, 5 trials):

```bash
sudo bash deploy/bench.sh
```

It runs eight configurations one after another and writes `REPORT.md`, raw JSON files and SVG
charts into the `--out` folder (default `results/`, which replaces the published results).
Open the report on Windows with `explorer.exe results-quick` from the Ubuntu window, or read it
in the terminal with `less results-quick/REPORT.md`.

---

## 9. Sign your own zone

```bash
sudo -s
export PATH=/opt/abhed/bin:/opt/abhed/sbin:$PATH
mkdir -p /tmp/myzone && cd /tmp/myzone
cat > example.test.zone <<'EOF'
$ORIGIN example.test.
$TTL 3600
@    IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@    IN NS  ns1
ns1  IN A   192.0.2.1
www  IN A   192.0.2.10
EOF
KEY=$(abhed-keygen -a mtl -k -d . example.test)
abhed-signzone -o example.test. -f example.test.signed -k "$KEY" -s state example.test.zone
abhed-sigdump example.test.signed
nsd-checkzone example.test example.test.signed
```

- `abhed-keygen -a mtl|mldsa44|ecdsap256 [-k] zone` creates a key; `-k` makes it a
  key-signing key (or a single key for everything).
- `abhed-signzone` signs the zone with one ML-DSA-44 signature over the Merkle ladder. The
  `state` folder keeps the tree: run the same command again after editing the zone and it
  continues the same series. **Never delete or copy `state` between zones.**
- `nsd-checkzone ... is ok` confirms the patched NSD accepts the file.

To serve it, add a `zone:` block for it to an NSD configuration and a matching trust anchor to
Unbound. The files in `/tmp/abhed-lab/etc/` are complete working examples to copy from.
The Unbound options added by the patch are in [`docs/USAGE.md`](USAGE.md).

This is a research testbed: **do not sign or serve real, public zones with it.**

---

## 10. Containers with Podman (optional)

A `Containerfile` builds the whole stack into one image. **It has not been tested yet**; the
native installation above is the supported path.

```bash
sudo apt-get install -y podman
sudo podman build -t abhed:2.1 .
sudo podman run --rm -it abhed:2.1                 # runs the end-to-end tests
sudo podman run --rm -it abhed:2.1 bash            # a shell with everything installed
```

Docker accepts the same file: `docker build -f Containerfile -t abhed:2.1 .`

---

## 11. Update, clean up, uninstall

| Task | Command |
|---|---|
| Get the latest version | `git pull` then `sudo bash deploy/build.sh` |
| Rebuild from scratch | `sudo bash deploy/build.sh --clean` |
| Delete a lab | `sudo bash deploy/lab.sh down DIR` then `sudo rm -rf DIR` |
| Remove downloaded sources | `sudo rm -rf .build` |
| Uninstall completely | `sudo rm -rf /opt/abhed` and delete the project folder |
| Remove the WSL Ubuntu (Windows) | in PowerShell: `wsl --unregister Ubuntu-24.04` (deletes everything in it) |
| Remove the Multipass VM (macOS) | `multipass delete abhed && multipass purge` |

The build packages from section 2 can stay; they are standard Ubuntu packages.

---

## 12. Troubleshooting

| Message or symptom | Cause and fix |
|---|---|
| `wsl --install` says the command is unknown | Windows is too old. Run Windows Update, or install WSL from the Microsoft Store. |
| WSL: "Please enable the Virtual Machine Platform" / error 0x80370102 | Virtualisation is off in the BIOS. See 1A step 1. |
| `xx missing tool: ...` | A package from section 2 is missing. Run the `apt-get install` line again. |
| `xx missing libldns development files` | `sudo apt-get install -y libldns-dev` |
| `Go 1.xx is too old` | Ubuntu 22.04 or older: `sudo apt-get remove -y golang-go && sudo snap install go --classic`, open a new terminal, build again. |
| `run as root` | Put `sudo bash` before the script, as shown. |
| `nothing built in /opt/abhed` | Run `sudo bash deploy/build.sh` first. |
| `fatal: unable to access 'https://github.com/...'` | No internet, or a proxy. Check `ping -c1 github.com`. |
| `error: patch failed` | `deploy/versions.env` was changed. The patches fit exactly the versions in the repository; restore it with `git checkout deploy/versions.env`. |
| `$'\r': command not found` | The scripts got Windows line endings (copied through Windows). Clone with `git` inside Ubuntu, or run `sudo apt-get install -y dos2unix && dos2unix deploy/*.sh`. |
| `lab up` fails, `address already in use` | Something else uses port 53 on 127.0.53.x, often a lab that is still running: `sudo bash deploy/lab.sh down DIR`. `sudo ss -lunp 'sport = :53'` shows who listens. On WSL, check networking is not "mirrored". |
| `DIR is not a lab` | Run `abhedctl init --dir DIR ...` first, or check the folder name. |
| `abhedctl: command not found` | The `export PATH=/opt/abhed/bin:/opt/abhed/sbin:$PATH` line was not run in this shell. |
| `dig` answer without `ad` | Query the resolver `@127.0.53.53` (not .10/.20/.30) and add `+dnssec`. |
| `SERVFAIL` everywhere | The resolver has old keys after a new `init` on the same folder: `sudo bash deploy/lab.sh restart-resolver DIR`. Details: `sudo bash deploy/lab.sh logs DIR`. |
| New name gives NXDOMAIN after `grow` | Run `sudo bash deploy/lab.sh reload DIR` (see 6.8). |
| Build is very slow on Windows | The project is under `/mnt/c`. Clone it again into `~` (section 3). |

Still stuck? Open an issue at https://github.com/drajdeep/ABHED-v2-native/issues with the
exact command, the last 20 lines of output, and the output of `cat /etc/os-release`,
`uname -m` and `go version`.
