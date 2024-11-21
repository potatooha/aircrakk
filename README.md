# aircrakk

This is a script to semiautomate work with aircrack-ng and hashcat.

## Why

- I hate being forced to repeat the same patterns (to do things right).
- I hate to use two terminals when trying to capture a handshake.
- I hate making garbage capture files without handshakes (they have to be deleted manually).
- I hate to download `cap2hccapx.bin`.
- I hate to manage sessions by hands.

## Requirements

- Linux (tested on Ubuntu 24.04),
- python 3.6 or newer (tested on 3.12.3),
- aircrack-ng (tested on 1.7),
- hashcat (tested on 6.2.6).

## How to use

Just download / clone the repo and use:

    python3 aircrakk.py <command> [command-specific-arg1] ...

### Dumping available access points

    python3 aircrakk.py dump <iface> [--sec time to monitor] [--output report file] [--hide_if_no_stations]

For example:

    python3 aircrakk.py dump wlo1 --output ~/crakk/list.txt

### Capturing handshakes

    python3 aircrakk.py handshake <iface> <fakeauth|deauth> <--channel n> <--bssid mac> <--output_dir basic output dir where dump files should be stored>

For example:

    python3 aircrakk.py hasdshake wlo1 deauth --channel 1 --bssid aa:de:ad:be:ef:aa --output_dir ~/crakk/

### (Optional) Preparing wordlists

The kernel has a limit on password length. So you can't use `hashcat` for passwords that are shorter or longer than the supported range. If you care about this, you can split a wordlist into two: one can be used by `hashcat`, and one by `aircrack-ng`. For this:

    python3 aircrakk.py splitter <--wordlist path.lst>

For example:

    python3 aircrakk.py splitter rockme.txt

### Creating a task configuration file

When cracking, you can use many wordlists and/or masks. To create (an example of) the task file, you can use:

    python3 aircrakk.py tasks [--wordlist path.lst] [--wordlist_dir directory to scan for wordlists] [--mask brute-force attack mask] <--output tasks config file to create>

For example:

    python3 aircrakk.py tasks --wordlist ~/wordlists/rockme.lst --wordlist_dir ~/wordlists/downloaded --mask ?d?d?d?d?a?a?a?a --output ~/crakk/tasks.json

As a result, a json file of the following format will be created:

    {
        "?d?d?d?d?a?a?a?a": {"kind": "mask"},
        "/home/user/wordlists/rockme.lst": {"kind": "wordlist", "comment": "1024 bytes"},
        "/home/user/wordlists/downloaded/rollme.lst": {"kind": "wordlist", "comment": "64 bytes"},
    }

Most likely you will want to edit it manually. I hope it will not be difficult. After you get familiar with the file format, you will be able to create one manually and/or fine-tune it.

### Cracking

    python3 aircrackk.py crack <--capture an input .cap file> <--tasks task configuration file> <--statistics task statistics file (will create new one if not exists)> [--progress cracking progress file (will create new one if not exists; the default path is next to a .cap file)] [--workload_profile hashcat workload profile] [--prefer_aircrack]

For example:

    python3 aircrackk.py crack --capture ~/crakk/aadeadbeefaa/dump-01.cap --tasks ~/crakk/tasks.json --statistics ~/crakk/stats.json
