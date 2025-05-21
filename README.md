# Deezer2EchoMini: Enhanced Deezer Downloader for FiiO SnowSky Echo Mini 

This fork of the [Deezer Downloader](https://github.com/kmille/deezer-downloader) project adds complete FLAC support optimized for the FiiO SnowSky Echo Mini portable music player. Infinite thanks to @kmille, the original creator, without whose brilliant work and dedication this project would be totally impossible. His excellent codebase has made these specific improvements for the Echo Mini possible.

### 🆕 Added Features:
- **Optimized Album Covers**: Automatically converts all album covers to 750px × 750px JPG with baseline encoding for faster loading on the Echo Mini
- **Enhanced Metadata Support**: 
  - Use Vorbis for Flac files instead a id3
  - Preserves and properly formats all original metadata
  - Adds genre tags when available
  - Intelligent release date handling (randomizes day/month when artists only specify the year as 01-01-YYYY)
- **Echo Mini Compatibility**: Transfer your downloaded playlists and albums directly to your FiiO SnowSky Echo Mini for perfect metadata display and playback experience, this is only for flacs files.

Simply download your favorite music and transfer the folders to your Echo Mini - all metadata will be recognized perfectly without any compatibility issues!

---

# Deezer Downloader 🎶 🎧 💃 🦄

### Download music from Deezer and Spotify with a simple web frontend, through a local-hosted service written in Python.

### Features
- download songs, albums, public playlists from Deezer.com (account is required)
- download Spotify playlists (by parsing the Spotify website and download the songs from Deezer)
- download as zip file (including m3u8 playlist file)
- quality: flac or 320 kbit/s mp3 with premium subscription or 128 kbit/s MP3s with free subscription
- ID3-Tags and embedded album cover
- download songs via yt-dlp
- KISS (keep it simple and stupid) front end
- MPD integration (use it on a Raspberry Pi!)
- simple REST api
- proxy support (https/socks5)

## Table of Contents:
- [Deezer2EchoMini: Enhanced Deezer Downloader for FiiO SnowSky Echo Mini](#deezer2echomini-enhanced-deezer-downloader-for-fiio-snowsky-echo-mini)
    - [🆕 Added Features:](#-added-features)
- [Deezer Downloader 🎶 🎧 💃 🦄](#deezer-downloader----)
    - [Download music from Deezer and Spotify with a simple web frontend, through a local-hosted service written in Python.](#download-music-from-deezer-and-spotify-with-a-simple-web-frontend-through-a-local-hosted-service-written-in-python)
    - [Features](#features)
  - [Table of Contents:](#table-of-contents)
  - [Get started](#get-started)
    - [1. Install Python](#1-install-python)
    - [2. Install deezer2EchoMini](#2-install-deezer2echomini)
    - [3. Retrieve your `arl` cookie](#3-retrieve-your-arl-cookie)
    - [4. Set the config file](#4-set-the-config-file)
    - [5. Run deezer-downloader](#5-run-deezer-downloader)
    - [6. Access the frontend](#6-access-the-frontend)
  - [Settings](#settings)
  - [Specific use cases](#specific-use-cases)
    - [Run as systemd service](#run-as-systemd-service)
    - [Developer setup](#developer-setup)
    - [Deployment with Ansible](#deployment-with-ansible)
  - [Screenshots](#screenshots)
  - [Shortcuts](#shortcuts)
  - [Tests](#tests)
  - [Changelog](#changelog)
    - [Custom Version 2.1.0 Echo Mini (21.05.2025)](#custom-version-210-echo-mini-21052025)
    - [Version 2.0.0 (27.03.2023)](#version-200-27032023)
    - [Version 1.3.3 (27.12.2021)](#version-133-27122021)
    - [Version 1.3.2 (26.11.2021)](#version-132-26112021)
    - [Version 1.3.1 (21.01.2021)](#version-131-21012021)
    - [Version 1.3 (05.11.2020)](#version-13-05112020)
    - [Version 1.2 (01.11.2020)](#version-12-01112020)
    - [Version 1.1 (13.05.2020)](#version-11-13052020)

## Get started

### 1. Install Python
[python.org](https://www.python.org/about/)

### 2. Install deezer2EchoMini
```bash
# Clone the repository
git clone https://github.com/Alexeido/deezer2EchoMini.git
cd deezer2EchoMini

# Install using pip
pip install --user .

# Or to install in development mode (changes to code will be reflected immediately)
pip install --user -e .

# Run the application
deezer-downloader --show-config-template > config.ini
# Edit the config.ini file to add your arl cookie and other settings
deezer-downloader --config config.ini
```

Note: This will install the FiiO SnowSky Echo Mini optimized version with all enhanced metadata and album cover features. Do not use `pip install deezer-downloader` as that would install the original version without the Echo Mini optimizations.

### 3. Retrieve your `arl` cookie

On Firefox or Chrome-based browser:
- Log into your Deezer account
- Open the DevTools (`F12` or `Ctrl+Shift+C` or `Ctrl+Shift+I`)
- Go to `Storage` tab
- In the cookies, find `arl`: a ~200 characters alphanumeric key

### 4. Set the config file
Retrieve the template: 
```bash 
deezer-downloader --show-config-template > config.ini
```
You need to set at least:
- under `[deezer]`: `cookie_arl`, your arl cookie
- under `[youtubedl]`: `command`, your yt-dlp install path\

**Simple yt-dlp setup:**
1. Download the latest yt-dlp executable from https://github.com/yt-dlp/yt-dlp/releases
2. Place it in the same directory as your deezer-downloader
3. In your config.ini file, set the command to `./yt-dlp` (on Linux/Mac) or `.\yt-dlp.exe` (on Windows)

As stated in the config template, deezer-downloader does NOT keep yt-dlp updated, you will have to monitor this yourself.

Check [Settings](#settings) for further instructions.

### 5. Run deezer-downloader
```bash
deezer-downloader --config config.ini
```

### 6. Access the frontend
Unless specified differently in the config file, the default frontend address is: http://localhost:5000.
Access it with your favourite web browser.

Check [Screenshots](#screenshots) if needed.

Enjoy! 🦄

## Settings

There is a settings file template called `settings.ini.example`. You can specify the download directory with  `download_dir`. Pressing the download button only downloads the song/album/playlist. If you set `use_mpd=True` in the `settings.ini` the backend will connect to mpd (localhost:6600) and update the music database. Pressing the play button will download the music. If `use_mpd=True`  is set the mpd database will be updated and the song/album/playlist will be added to the playlist. In `settings.ini` `music_dir` should be the music root location of mpd. The `download_dir` must be a subdirectory of `music_dir`. 

As Deezer sometimes requires a captcha to login the auto login features was removed. Instead you have to manually insert a valid Deezer cookie to the `settings.ini`. The relevant cookie is the `arl` cookie.

```bash
kmille@linbox:deezer-downloader poetry run deezer-downloader --help
usage: deezer-downloader [-h] [-v] [-t] [-c CONFIG]

Download music from Deezer with a nice front end

options:
  -h, --help            show this help message and exit
  -v, --version         show version and exit
  -t, --show-config-template
                        show config template. At least you have to insert the ARL cookie
  -c CONFIG, --config CONFIG
                        config file - if not supplied, the following directories are considered looking for deezer-downloader.ini: current working directory, XDG_CONFIG_HOME environment variable, ~/.config, /etc)

kmille@linbox:deezer-downloader poetry run deezer-downloader --config settings.ini
Starting Threadpool
/home/kmille/.cache/pypoetry/virtualenvs/deezer-downloader-NFDPq16k-py3.11/lib/python3.11/site-packages/giphypop.py:241: UserWarning: You are using the giphy public api key. This should be used for testing only and may be deactivated in the future. See https://github.com/Giphy/GiphyAPI.
  warnings.warn('You are using the giphy public api key. This '
Worker 0 is waiting for a task
Worker 1 is waiting for a task
Worker 2 is waiting for a task
Worker 3 is waiting for a task
Worker 0 is now working on task: {'track_id': 8086130, 'add_to_playlist': False}
Downloading 'Adele - Set Fire to the Rain.mp3'
Dowload finished: /tmp/deezer-downloader/songs/Adele - Set Fire to the Rain.mp3
Setting state to mission accomplished to worker 0
worker 0 is done with task: {'track_id': 8086130, 'add_to_playlist': False} (state=mission accomplished)
```

## Specific use cases

### Run as systemd service

We use it with nginx and [ympd](https://github.com/notandy/ympd) as mpd frontend:
- / goes to ympd
- /d/ goes to the downloader

The deployment directory contains a systemd unit file and a nginx vhost config file. There is also a [patch](https://github.com/kmille/music-ansible/blob/master/roles/ympd/files/fix_header.patch) to add a link to the ympd frontend. The `debug` tab will show you the debug output of the app.Shortcuts

If you want to debug or build it from source: there is a docker-compose file in the docker directory. The `docker/downloads` directory is mounted into the container and will be used as download directory. You have to check the permissions of the `docker/downloads` directory as docker mounts it with the same owner/group/permissions as on the host. The `deezer` user in the docker container has uid 1000. If you also have the uid 1000 then there should be no problem. For debugging: `sudo docker-compose build --force-rm && sudo docker-compose up`

### Developer setup
Tested on Ubuntu Jammy:

```bash
  sudo apt-get update -q
  sudo apt-get install -qy vim tmux git ffmpeg

  # python3-poetry is too old (does not support groups ...)
  sudo apt-get install -qy python3-pip
  sudo pip install poetry
  git clone https://github.com/kmille/deezer-downloader.git
  cd deezer-downloader
  poetry install
  poetry run deezer-downloader --show-config-template > settings.ini

  # enable yt-dlp
  sudo pip install yt-dlp
  sed -i 's,.*command = /usr/bin/yt-dlp.*,command = /usr/local/bin/yt-dlp,' settings.ini

  # enable mpd
  sudo apt-get install -yq mpd ncmpcpp
  sudo sed -i 's,^music_directory.*,music_directory         "/tmp/deezer-downloader",' /etc/mpd.conf
  sudo systemctl restart mpd
  sed -i 's/.*use_mpd = False.*/use_mpd = True/' settings.ini

  # 1) Adjust the Deezer cookie: vim settings.ini
  # 2) Run tests: DEEZER_DOWNLOADER_CONFIG_FILE=settings.ini poetry run pytest -v -s
  # 3) Run it: poetry run deezer-downloader --config settings.ini
  # 4) Try out: ncmpcpp -h 127.0.0.1 && xdg-open http://localhost:5000
  # 5) Downloaded files are in /tmp/deezer-downloader
```

### Deployment with Ansible
Including mpd and ympd
https://github.com/kmille/music-ansible (not maintained anymore)


## Screenshots

Results
![](/docs/screenshots/2echomini.png)  
![](/docs/screenshots/1.jpg)  
![](/docs/screenshots/1.jpg)  
Accents includeds
![](/docs/screenshots/3.jpg)  

Search for songs. You can listen to a 30 second preview in the browser.  

![](/docs/screenshots/2020-05-13-211356_screenshot.png)  

Search for albums. You can download them as zip file.  

![](/docs/screenshots/2020-05-13-213544_screenshot.png)

List songs of an album.

![](/docs/screenshots/2020-05-13-211528_screenshot.png)

Download a Deezer playlist.    

![](/docs/screenshots/2020-05-13-211633_screenshot.png)  

ncmpcpp mpd client.  

![](/docs/screenshots/2020-05-13-212025_screenshot.png)  

## Shortcuts

`Ctrl`+`M`: focus search bar  
`Enter`: serach for songs   
`Alt`+`Enter`: search for albums  
`Ctrl`+`B`: go to / (this is where our ympd is)  
`Ctrl`+`Shift`+`[1-7]` switch tabs

## Tests

```bash
cd deezer-downloader
DEEZER_DOWNLOADER_CONFIG_FILE=settings.ini poetry run pytest -v -s
# If you don't set DEEZER_DOWNLOADER_CONFIG_FILE the default template file will be used. Some tests will fail because there is no valid arl_cookie.
```

## Changelog

### Custom Version 2.1.0 Echo Mini (21.05.2025)

- **FiiO SnowSky Echo Mini optimizations for Flacs**:
  - Convert album covers to 750px × 750px JPG with baseline encoding for faster loading
  - Use Vorbis metadata for FLAC files instead of ID3 tags for better compatibility
  - Add genre tags when available from Deezer
  - Implement intelligent release date handling (randomizes day/month when only year is specified)
  - Optimize metadata formatting for perfect display on Echo Mini devices


### Version 2.0.0 (27.03.2023)

- use poetry as build system
- build package and uploada to pypi
- worker threads now "daemon threads" (they now just stop if you stop deezer-downloader)
- update config template (remove http.debug)
- update dependencies
- switch to waitress (from gunicorn)

### Version 1.3.3 (27.12.2021)
- replace youtube-dl by yt-dl
- update third party dependencies

### Version 1.3.2 (26.11.2021)
- fix broken deezer download functionality (#66, removes the ability to download flac quality)
- update third party dependencies
- update ubuntu base image for the docker container

### Version 1.3.1 (21.01.2021)
- allow to set download quality (flac|mp3) via environment variable DEEZER_FLAC_QUALITY (#43)

### Version 1.3 (05.11.2020)

- feature: download your favorite Deezer songs
- automated tests with Github Actions
- push Docker image to [hub.docker.com](https://hub.docker.com/repository/docker/kmille2/deezer-downloader/general) with Github Actions

### Version 1.2 (01.11.2020)

- **breaking change:** now use the `arl` cookie instead of the `sid` cookie. This cookie does not expire so we don't need the background thread that keeps the session alive
- add support for flac as download format

### Version 1.1 (13.05.2020)

- thanks to [luelista](https://github.com/luelista) for the contribution!
- play 30 second preview in browser
- add Vagrantfile
- show album cover in search results
- use a threaded queue for download tasks
- list album songs
