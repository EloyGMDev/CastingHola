# CastingHola

**CastingHola** is a Python-based tool designed to **detect and interact with display devices capable of receiving media transmissions** (such as smart TVs, Chromecast, or compatible receivers). It allows the user to **send an image file (`Hola.png`) to all detected displays** or **stop the current playback**.

## Features

* Automatic detection of available cast-compatible devices.
* Option to transmit a local image (`Hola.png`) to all detected screens.
* Option to stop playback on all detected devices.
* Simple local HTTP server to serve the image for casting.
* Built-in legal disclaimer emphasizing responsible and authorized use.

## Requirements

* Python **3.8+**
* Dependencies:

  ```
  pychromecast
  requests
  ```

Install the dependencies with:

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Discover available devices
python CastHola.py --discover

# Serve Hola.png and cast it to all detected displays
python CastHola.py --serve --cast

# Stop playback on all detected displays
python CastHola.py --stop
```

Replace the file `Hola.png` in the same directory as the script before running it.

## Legal Notice

This software is intended **only for controlled environments**, such as testing networks or devices that you **own or have explicit permission to access**.
Unauthorized use on external networks or third-party devices **may violate applicable laws and regulations** and could result in **fines or legal action**.
The author **is not responsible for misuse or illegal activities** performed with this software.

