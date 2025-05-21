import base64
import sys
import re
import json
import time
from typing import Optional, Sequence

import requests
import json

from deezer_downloader.configuration import config

from Crypto.Hash import MD5
from Crypto.Cipher import Blowfish
import struct
import urllib.parse
import html.parser
import requests
from binascii import a2b_hex, b2a_hex

# Añade esta importación al principio del archivo
from mutagen.flac import FLAC
import os


# BEGIN TYPES
TYPE_TRACK = "track"
TYPE_ALBUM = "album"
TYPE_PLAYLIST = "playlist"
TYPE_ALBUM_TRACK = "album_track" # used for listing songs of an album
# END TYPES

session = None
sessionJwt = None
tmp_jwt = None
license_token = {}
sound_format = ""
USER_AGENT = "Mozilla/5.0 (X11; Linux i686; rv:135.0) Gecko/20100101 Firefox/135.0"

def get_genres_from_api(album_id):
    """
    Obtiene los géneros de un álbum usando la API pública de Deezer
    
    Args:
        album_id: ID del álbum en Deezer
        
    Returns:
        list: Lista de nombres de géneros o lista vacía si no se encuentran
    """
    try:
        # Usar la API pública de Deezer que no requiere autenticación
        url = f"https://api.deezer.com/album/{album_id}"
        response = requests.get(url)
        
        if response.status_code != 200:
            print(f"Error al obtener información del álbum {album_id}: {response.status_code}")
            return []
            
        data = response.json()
        # Extraer géneros
        genres = []
        if "genres" in data and "data" in data["genres"]:
            for genre in data["genres"]["data"]:
                if "name" in genre:
                    genres.append(genre["name"])
            
            #print(f"Géneros encontrados en API para álbum {album_id}: {genres}")
            return genres
        else:
            #print(f"No se encontraron géneros en la API para álbum {album_id}")
            return []
            
    except Exception as e:
        print(f"Error obteniendo géneros desde API: {e}")
        return []

def get_track_info_from_api(track_id):
    """
    Obtiene información adicional de una canción usando la API pública de Deezer
    
    Args:
        track_id: ID de la canción en Deezer
        
    Returns:
        dict: Diccionario con metadatos adicionales o None si hay error
    """
    try:
        url = f"https://api.deezer.com/track/{track_id}"
        response = requests.get(url)
        
        if response.status_code != 200:
            print(f"Error al obtener información de la canción {track_id}: {response.status_code}")
            return None
            
        data = response.json()
        
        return data
    except Exception as e:
        print(f"Error obteniendo información de canción desde API: {e}")
        return None


def get_user_data() -> tuple[str, str]:
    try:
        user_data = session.get('https://www.deezer.com/ajax/gw-light.php?method=deezer.getUserData&input=3&api_version=1.0&api_token=')
        user_data_json = user_data.json()['results']
        options = user_data_json['USER']['OPTIONS']
        license_token = options['license_token']
        web_sound_quality = options['web_sound_quality']
        return license_token, web_sound_quality
    except (requests.exceptions.RequestException, KeyError) as e:
        print(f"ERROR: Could not get license token: {e}")


# quality_config comes from config file
# web_sound_quality is a dict coming from Deezer API and depends on ARL cookie (premium subscription)
def set_song_quality(quality_config: str, web_sound_quality: dict):
    global sound_format
    flac_supported = web_sound_quality['lossless'] is True
    if flac_supported:
        if quality_config == "flac":
            sound_format = "FLAC"
        else:
            sound_format = "MP3_320"
    else:
        if quality_config == "flac":
            print("WARNING: flac quality is configured in config file but not supported (no premium subscription?). Falling back to mp3")
        sound_format = "MP3_128"


def get_file_extension() -> str:
    return "flac" if sound_format == "FLAC" else "mp3"


# quality is mp3 or flac
def init_deezer_session(proxy_server: str, quality: str) -> None:
    global session, license_token, web_sound_quality
    header = {
        'Pragma': 'no-cache',
        'Origin': 'https://www.deezer.com',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9',
        'User-Agent': USER_AGENT,
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Cache-Control': 'no-cache',
        'X-Requested-With': 'XMLHttpRequest',
        'Connection': 'keep-alive',
        'Referer': 'https://www.deezer.com/login',
        'DNT': '1',
    }
    session = requests.session()
    session.headers.update(header)
    session.cookies.update({'arl': config['deezer']['cookie_arl'], 'comeback': '1'})
    if len(proxy_server.strip()) > 0:
        print(f"Using proxy {proxy_server}")
        session.proxies.update({"https": proxy_server})
    license_token, web_sound_quality = get_user_data()
    set_song_quality(quality, web_sound_quality)
    init_deezer_session_lrc()

def init_deezer_session_lrc() -> None:
    """
    Initialize the Deezer session for LRC (lyrics) functionality using raw config values
    to avoid interpolation issues with % characters in cookies.
    """
    # Verificar si existen las opciones necesarias
    has_jwt = config.has_option('deezer', 'cookie_fixed_jwt')
    has_refresh_d = config.has_option('deezer', 'cookie_refresh_token_D')
    has_refresh = config.has_option('deezer', 'cookie_refresh_token')
    
    # Obtener los valores usando el parser raw directamente para evitar interpolación
    if has_jwt and has_refresh_d and has_refresh:
        # Leer valores sin interpolación
        jwt = config['deezer'].get('cookie_fixed_jwt', raw=True)
        refresh_token_d = config['deezer'].get('cookie_refresh_token_D', raw=True)
        refresh_token = config['deezer'].get('cookie_refresh_token', raw=True)
        
        if jwt and refresh_token_d and refresh_token:
            #print("Using Deezer cookies for LRC")
            global sessionJwt, tmp_jwt
            sessionJwt = requests.Session()
            tmp_jwt = jwt
            
            # Cookies de autenticación
            sessionJwt.cookies.set('arl', config['deezer']['cookie_arl'], domain='deezer.com')
            sessionJwt.cookies.set('refresh-token', refresh_token, domain='deezer.com')
            sessionJwt.cookies.set('refresh-token-deezer', refresh_token_d, domain='deezer.com')
            sessionJwt.cookies.set('jwt', jwt, domain='deezer.com')
            sessionJwt.cookies.set('jwt-Deezer', jwt, domain='deezer.com')
    else:
        print("Mode Without Lyrics.")
        if has_jwt or has_refresh_d or has_refresh:
            if not has_jwt:
                print("WARNING: Missing cookie_fixed_jwt in config file.")
            if not has_refresh_d:
                print("WARNING: Missing cookie_refresh_token_D in config file.")
            if not has_refresh:
                print("WARNING: Missing cookie_refresh_token in config file.")

class Deezer404Exception(Exception):
    pass


class Deezer403Exception(Exception):
    pass


class DeezerApiException(Exception):
    pass


class ScriptExtractor(html.parser.HTMLParser):
    """ extract <script> tag contents from a html page """
    def __init__(self):
        html.parser.HTMLParser.__init__(self)
        self.scripts = []
        self.curtag = None

    def handle_starttag(self, tag, attrs):
        self.curtag = tag.lower()

    def handle_data(self, data):
        if self.curtag == "script":
            self.scripts.append(data)

    def handle_endtag(self, tag):
        self.curtag = None


def md5hex(data):
    """ return hex string of md5 of the given string """
    # type(data): bytes
    # returns: bytes
    h = MD5.new()
    h.update(data)
    return b2a_hex(h.digest())


def calcbfkey(songid):
    """ Calculate the Blowfish decrypt key for a given songid """
    key = b"g4el58wc0zvf9na1"
    songid_md5 = md5hex(songid.encode())

    xor_op = lambda i: chr(songid_md5[i] ^ songid_md5[i + 16] ^ key[i])
    decrypt_key = "".join([xor_op(i) for i in range(16)])
    return decrypt_key


def blowfishDecrypt(data, key):
    iv = a2b_hex("0001020304050607")
    c = Blowfish.new(key.encode(), Blowfish.MODE_CBC, iv)
    return c.decrypt(data)

def is_jwt_expired(token):
    try:
        payload_b64 = token.split('.')[1]
        padding = '=' * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(payload_json)
        exp = payload.get('exp')
        
        # Use UTC time to match JWT standard timestamps (always in UTC)
        now = int(time.time())
        
        delta = exp - now
        if delta <= 60:
            #print(f"❌ JWT expirado o por espirar en un minuto.")
            return True
        else:
            # Convert to human-readable format with time zone info
            #exp_datetime = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(exp))
            #local_exp = time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(exp))
            #print(f"✅ JWT válido. Expira: {exp_datetime} ({local_exp} hora local)")
            #print(f"   Tiempo restante: {delta//3600} horas y {(delta%3600)//60} minutos.")
            return False
    except Exception as e:
        print(f"⚠️ Error al decodificar JWT: {e}")
        return True
# Construcción de sesión con todas las cookies fijas

def updateCookies():
    """
    Detect de JWT cookie and update the session has to be done
    """
    global sessionJwt, tmp_jwt
    if sessionJwt:
        sessionLrc = sessionJwt
        if is_jwt_expired(tmp_jwt):
            url = "https://auth.deezer.com/login/renew?jo=p&rto=c&i=c"
            headers = {
                "Origin": "https://www.deezer.com",
                "Referer": "https://www.deezer.com/",
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0"
            }
            #print("\n--- Enviando renovación JWT ---")
            #print("URL:   ", url)
            #print("Headers:", headers)
            #print("Cookies:", session.cookies.get_dict())

            r = sessionJwt.post(url, headers=headers)
            #print("Status code:", r.status_code)
            #print("Body respuesta:", r.text)

            if r.ok:
                new_jwt = r.json().get('jwt')
                #print("→ Nuevo JWT")
                sessionLrc.cookies.set('jwt', new_jwt, domain='deezer.com')
                sessionLrc.cookies.set('jwt-Deezer', new_jwt, domain='deezer.com')
                # Almacenar en la variable de sesión
                tmp_jwt = new_jwt
                return new_jwt
            else:
                print("❌ No se pudo renovar JWT")
                return None

def decryptfile(fh, key, fo):
    """
    Decrypt data from file <fh>, and write to file <fo>.
    decrypt using blowfish with <key>.
    Only every third 2048 byte block is encrypted.
    """
    blockSize = 2048
    i = 0

    for data in fh.iter_content(blockSize):
        if not data:
            break

        isEncrypted = ((i % 3) == 0)
        isWholeBlock = len(data) == blockSize

        if isEncrypted and isWholeBlock:
            data = blowfishDecrypt(data, key)

        fo.write(data)
        i += 1


def writeid3v1_1(fo, song):

    # Bugfix changed song["SNG_TITLE... to song.get("SNG_TITLE... to avoid 'key-error' in case the key does not exist
    def song_get(song, key):
        try:
            return song.get(key).encode('utf-8')
        except:
            return b""

    def album_get(key):
        try:
            return album_Data.get(key).encode('utf-8')
        except:
            return b""

    # what struct.pack expects
    # B => int
    # s => bytes
    data = struct.pack("3s" "30s" "30s" "30s" "4s" "28sB" "H"  "B",
                       b"TAG",                                            # header
                       song_get(song, "SNG_TITLE"),                       # title
                       song_get(song, "ART_NAME"),                        # artist
                       song_get(song, "ALB_TITLE"),                       # album
                       album_get("PHYSICAL_RELEASE_DATE"),                # year
                       album_get("LABEL_NAME"), 0,                        # comment
                       int(song_get(song, "TRACK_NUMBER")),               # tracknum
                       255                                                # genre
                       )

    fo.write(data)


def downloadpicture(pic_idid):
    resp = session.get(get_picture_link(pic_idid))
    return resp.content


def get_picture_link(pic_idid):
    setting_domain_img = "https://e-cdns-images.dzcdn.net/images"
    url = setting_domain_img + "/cover/" + pic_idid + "/1200x1200.jpg"
    return url


def writeid3v2(fo, song):

    def make28bit(x):
        return ((x << 3) & 0x7F000000) | ((x << 2) & 0x7F0000) | (
               (x << 1) & 0x7F00) | (x & 0x7F)

    def maketag(tag, content):
        return struct.pack(">4sLH", tag.encode("ascii"), len(content), 0) + content

    def album_get(key):
        try:
            return album_Data.get(key)
        except:
            #raise
            return ""

    def song_get(song, key):
        try:
            return song[key]
        except:
            #raise
            return ""

    def makeutf8(txt):
        #return b"\x03" + txt.encode('utf-8')
        return "\x03{}".format(txt).encode()

    def makepic(data):
        # Picture type:
        # 0x00     Other
        # 0x01     32x32 pixels 'file icon' (PNG only)
        # 0x02     Other file icon
        # 0x03     Cover (front)
        # 0x04     Cover (back)
        # 0x05     Leaflet page
        # 0x06     Media (e.g. lable side of CD)
        # 0x07     Lead artist/lead performer/soloist
        # 0x08     Artist/performer
        # 0x09     Conductor
        # 0x0A     Band/Orchestra
        # 0x0B     Composer
        # 0x0C     Lyricist/text writer
        # 0x0D     Recording Location
        # 0x0E     During recording
        # 0x0F     During performance
        # 0x10     Movie/video screen capture
        # 0x11     A bright coloured fish
        # 0x12     Illustration
        # 0x13     Band/artist logotype
        # 0x14     Publisher/Studio logotype
        imgframe = (b"\x00",                 # text encoding
                    b"image/jpeg", b"\0",    # mime type
                    b"\x03",                 # picture type: 'Cover (front)'
                    b""[:64], b"\0",         # description
                    data
                    )

        return b'' .join(imgframe)

    # get Data as DDMM
    try:
        phyDate_YYYYMMDD = album_get("PHYSICAL_RELEASE_DATE") .split('-') #'2008-11-21'
        phyDate_DDMM = phyDate_YYYYMMDD[2] + phyDate_YYYYMMDD[1]
    except:
        phyDate_DDMM = ''

    # get size of first item in the list that is not 0
    try:
        FileSize = [
            song_get(song, i)
            for i in (
                'FILESIZE_AAC_64',
                'FILESIZE_MP3_320',
                'FILESIZE_MP3_256',
                'FILESIZE_MP3_64',
                'FILESIZE',
                ) if song_get(song, i)
            ][0]
    except:
        FileSize = 0

    try:
        track = "%02s" % song["TRACK_NUMBER"]
        track += "/%02s" % album_get("TRACKS")
    except:
        pass

    # http://id3.org/id3v2.3.0#Attached_picture
    id3 = [
        maketag("TRCK", makeutf8(track)),     # The 'Track number/Position in set' frame is a numeric string containing the order number of the audio-file on its original recording. This may be extended with a "/" character and a numeric string containing the total numer of tracks/elements on the original recording. E.g. "4/9".
        maketag("TLEN", makeutf8(str(int(song["DURATION"]) * 1000))),     # The 'Length' frame contains the length of the audiofile in milliseconds, represented as a numeric string.
        maketag("TORY", makeutf8(str(album_get("PHYSICAL_RELEASE_DATE")[:4]))),     # The 'Original release year' frame is intended for the year when the original recording was released. if for example the music in the file should be a cover of a previously released song
        maketag("TYER", makeutf8(str(album_get("DIGITAL_RELEASE_DATE")[:4]))),     # The 'Year' frame is a numeric string with a year of the recording. This frames is always four characters long (until the year 10000).
        maketag("TDAT", makeutf8(str(phyDate_DDMM))),     # The 'Date' frame is a numeric string in the DDMM format containing the date for the recording. This field is always four characters long.
        maketag("TPUB", makeutf8(album_get("LABEL_NAME"))),     # The 'Publisher' frame simply contains the name of the label or publisher.
        maketag("TSIZ", makeutf8(str(FileSize))),     # The 'Size' frame contains the size of the audiofile in bytes, excluding the ID3v2 tag, represented as a numeric string.
        maketag("TFLT", makeutf8("MPG/3")),

        ]  # decimal, no term NUL
    id3.extend([
        maketag(ID_id3_frame, makeutf8(song_get(song, ID_song))) for (ID_id3_frame, ID_song) in \
        (
            ("TALB", "ALB_TITLE"),   # The 'Album/Movie/Show title' frame is intended for the title of the recording(/source of sound) which the audio in the file is taken from.
            ("TPE1", "ART_NAME"),   # The 'Lead artist(s)/Lead performer(s)/Soloist(s)/Performing group' is used for the main artist(s). They are seperated with the "/" character.
            ("TPE2", "ART_NAME"),   # The 'Band/Orchestra/Accompaniment' frame is used for additional information about the performers in the recording.
            ("TPOS", "DISK_NUMBER"),   # The 'Part of a set' frame is a numeric string that describes which part of a set the audio came from. This frame is used if the source described in the "TALB" frame is divided into several mediums, e.g. a double CD. The value may be extended with a "/" character and a numeric string containing the total number of parts in the set. E.g. "1/2".
            ("TIT2", "SNG_TITLE"),   # The 'Title/Songname/Content description' frame is the actual name of the piece (e.g. "Adagio", "Hurricane Donna").
            ("TSRC", "ISRC"),   # The 'ISRC' frame should contain the International Standard Recording Code (ISRC) (12 characters).
        )
    ])

    try:
        genres = []
        if "GENRES" in album_Data and album_Data["GENRES"]:
            for genre_info in album_Data["GENRES"]:
                if "name" in genre_info:
                    genres.append(genre_info["name"])
            if genres:
                genre_str = "; ".join(genres)
                id3.append(maketag("TCON", makeutf8(genre_str)))  # Genre Content Type
    except Exception as e:
        print(f"ERROR: Could not add genre information to ID3: {e}")

    # Añade etiqueta para el año original de lanzamiento si está disponible
    try:
        if "ORIGINAL_RELEASE_DATE" in album_Data and album_Data["ORIGINAL_RELEASE_DATE"]:
            original_year = str(album_Data["ORIGINAL_RELEASE_DATE"][:4])
            id3.append(maketag("TORY", makeutf8(original_year)))  # Original Release Year
    except Exception as e:
        print(f"ERROR: Could not add original release year to ID3: {e}")




    try:
        id3.append(maketag("APIC", makepic(downloadpicture(song["ALB_PICTURE"]))))
    except Exception as e:
        print("ERROR: no album cover?", e)

    id3data = b"".join(id3)
#>      big-endian
#s      char[]  bytes
#H      unsigned short  integer 2
#B      unsigned char   integer 1
#L      unsigned long   integer 4

    hdr = struct.pack(">"
                      "3s" "H" "B" "L",
                      "ID3".encode("ascii"),
                      0x300,   # version
                      0x00,    # flags
                      make28bit(len(id3data)))

    fo.write(hdr)
    fo.write(id3data)


def get_song_url(track_token: str, quality: int = 3) -> str:
    try:
        response = requests.post(
            "https://media.deezer.com/v1/get_url",
            json={
                'license_token': license_token,
                'media': [{
                    'type': "FULL",
                    "formats": [
                        {"cipher": "BF_CBC_STRIPE", "format": sound_format}]
                }],
                'track_tokens': [track_token,]
            },
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Could not retrieve song URL: {e}")

    if not data.get('data') or 'errors' in data['data'][0]:
        raise RuntimeError(f"Could not get download url from API: {data['data'][0]['errors'][0]['message']}")

    url = data['data'][0]['media'][0]['sources'][0]['url']
    return url


def add_vorbis_tags(song: dict, output_file: str) -> None:
    """
    Add Vorbis comments to a FLAC file
    """
    #print(f"Adding Vorbis comments to FLAC file: {output_file}")
    # Primero guardamos en un log los metadatos de la canción en un archivo song_data que tendra el nombre y sus metadatos
    # con el nombre de la cancion

    try:
        audio = FLAC(output_file)
        
        # Clear existing tags
        audio.clear()
        
        # Map Deezer metadata to Vorbis tags
        if "SNG_TITLE" in song:
            audio["TITLE"] = song["SNG_TITLE"]
        if "ART_NAME" in song:
            audio["ARTIST"] = song["ART_NAME"]
        if "ALB_TITLE" in song:
            audio["ALBUM"] = song["ALB_TITLE"]
        if "TRACK_NUMBER" in song:
            audio["TRACKNUMBER"] = str(song["TRACK_NUMBER"])
        if "DISK_NUMBER" in song:
            audio["DISCNUMBER"] = str(song["DISK_NUMBER"])
        if "ISRC" in song:
            audio["ISRC"] = song["ISRC"]
        if "DURATION" in song:
            audio["LENGTH"] = str(song["DURATION"])

        # Obtener metadatos del álbum si tenemos un album_id
        album_metadata = None
        if "ALB_ID" in song:
            #print(f"Fetching album metadata for '{song.get('ALB_TITLE', 'Unknown album')}' (Album ID: {song['ALB_ID']})")
            album_metadata = get_album_metadata(song['ALB_ID'])

        # Add genre information usando múltiples fuentes
        try:
            genres = []
            # 1. First try to get genres from the song itself
            if "GENRES" in song and song["GENRES"]:
                for genre_info in song["GENRES"]:
                    if "name" in genre_info:
                        genres.append(genre_info["name"])
            
            # 2. If no genres in song, try album metadata
            if not genres and album_metadata and "GENRES" in album_metadata and album_metadata["GENRES"]:
                for genre_info in album_metadata["GENRES"]:
                    if "name" in genre_info:
                        genres.append(genre_info["name"])
            
            # 3. Si aún no tenemos géneros, intentar con la API pública de Deezer (album)
            if not genres and "ALB_ID" in song:
                api_genres = get_genres_from_api(song["ALB_ID"])
                if api_genres:
                    genres = api_genres
            
            # 4. Como último recurso, intentar con la API de track
            if not genres and "SNG_ID" in song:
                track_info = get_track_info_from_api(song["SNG_ID"])
                if track_info and "album" in track_info and "genre_id" in track_info["album"]:
                    # Si tenemos el genre_id, obtengamos el nombre del género
                    try:
                        genre_url = f"https://api.deezer.com/genre/{track_info['album']['genre_id']}"
                        genre_resp = requests.get(genre_url)
                        if genre_resp.status_code == 200:
                            genre_data = genre_resp.json()
                            if "name" in genre_data and genre_data["name"] != "Todos":
                                genres.append(genre_data["name"])
                                #print(f"Using genre from Deezer Genre API: {genres}")
                    except Exception as e:
                        print(f"Error getting genre name: {e}")
            
            # 5. Set genres in tags - MODIFICADO PARA USAR PUNTO Y COMA (;) COMO SEPARADOR
            if genres:
                # Lista para almacenar todos los géneros después de dividir los que vienen con punto y coma
                genres_final = []
                
                # Procesar cada género y dividir los que vengan con punto y coma
                for genre in genres:
                    if ";" in genre:
                        # Si el género contiene punto y coma, lo dividimos
                        split_genres = [g.strip() for g in genre.split(";")]
                        genres_final.extend(split_genres)
                    else:
                        genres_final.append(genre)
                
                # Aseguramos que no hay géneros duplicados ni vacíos
                genres_final = [g for g in list(dict.fromkeys(genres_final)) if g]
                
                # En FLAC podemos poner los géneros como valores múltiples O como un solo string con separadores
                # Implementamos ambas formas para máxima compatibilidad
                
                # 1. Como valores múltiples (etiquetas separadas)
                audio["GENRE"] = genres_final
                
                # 2. Como un solo string con separador punto y coma (,)
                genre_string = ", ".join(genres_final)
                audio["GENRETEXT"] = genre_string  # Campo adicional para asegurar compatibilidad
                
                #print(f"Added genres: {genres_final} ('{genre_string}')")
        
                
        except Exception as e:
            print(f"ERROR: Could not add genre information: {e}")
                
        # Add release dates - NUEVA IMPLEMENTACIÓN MEJORADA PARA WINDOWS
        try:
            # Determinar qué fecha usar (priorizar original release date)
            release_date = None
            # 2. Si no hay fecha de API, usar fuentes tradicionales
            if not release_date:
                # Primero intenta usar la fecha original de la canción
                if "ORIGINAL_RELEASE_DATE" in song:
                    release_date = song["ORIGINAL_RELEASE_DATE"]
                    source = "song original"
                # Si no hay original, intenta physical
                elif "PHYSICAL_RELEASE_DATE" in song:
                    release_date = song["PHYSICAL_RELEASE_DATE"]
                    source = "song physical"
                # Si no hay fechas en la canción, intenta del álbum
                elif album_metadata:
                    if "ORIGINAL_RELEASE_DATE" in album_metadata:
                        release_date = album_metadata["ORIGINAL_RELEASE_DATE"]
                        source = "album original"
                    elif "PHYSICAL_RELEASE_DATE" in album_metadata:
                        release_date = album_metadata["PHYSICAL_RELEASE_DATE"]
                        source = "album physical"
            
            if release_date:
                # Extraer año, mes, día
                year = release_date[:4]
                
                # Añadir todos los campos de fecha que Windows y otros reproductores podrían reconocer
                #print(f"Using {source} release date: {release_date}")
                
                # Si la fecha tiene el mes y dia 1 lo aleatorizamos a un mes y dia random
                if release_date[5:7] == "01" and release_date[8:10] == "01":
                    import random
                    month = str(random.randint(1, 12)).zfill(2)
                    if month == "02":
                        day = str(random.randint(1, 28)).zfill(2)
                    elif month in ["04", "06", "09", "11"]:
                        day = str(random.randint(1, 30)).zfill(2)
                    else:
                        day = str(random.randint(1, 31)).zfill(2)
                    release_date = f"{year}-{month}-{day}"
                    #print(f"Randomized release date: {release_date}")

                # Formato estándar YYYY-MM-DD que reconoce Windows
                audio["DATE"] = release_date
                
                # Campo de año para reproductores más antiguos
                audio["YEAR"] = year
                
                # Para Windows Media Player y propiedades de Windows
                audio["WM/YEAR"] = year
                
                # Para reproductores que buscan información específica de fecha
                audio["ORIGINALDATE"] = release_date
                audio["ORIGINALYEAR"] = year
                
                # Añadir explícitamente para properzone Title - Año
                if "SNG_TITLE" in song:
                    audio["TITLE"] = song["SNG_TITLE"]
                
                # Más campos de fecha específicos para Windows
                date_parts = release_date.split("-")
                if len(date_parts) >= 3:
                    # Añadir fecha de lanzamiento en formato que Windows reconoce
                    audio["RELEASETIME"] = release_date
                    audio["RELEASEDATE"] = release_date
                    
                    # Para Windows Explorer/Media Player
                    audio["WM/ORIGINALRELEASETIME"] = release_date
                    audio["WM/ORIGINALRELEASEYEAR"] = year
                    
                #print(f"Added comprehensive date information: {release_date} (Year: {year})")
            else:
                print("No release date information found")
                
        except Exception as e:
            print(f"ERROR: Could not add release date information: {e}")
            
        # Add label name if available (try from API first)
        try:
            label_added = False
            # 1. Intentar obtener etiqueta desde la API si tenemos album_id
            if "ALB_ID" in song and not label_added:
                try:
                    album_api_url = f"https://api.deezer.com/album/{song['ALB_ID']}"
                    album_api_resp = requests.get(album_api_url)
                    if album_api_resp.status_code == 200:
                        album_api_data = album_api_resp.json()
                        if "label" in album_api_data and album_api_data["label"]:
                            audio["ORGANIZATION"] = album_api_data["label"]
                            audio["PUBLISHER"] = album_api_data["label"]
                            #print(f"Added label from Deezer API: {album_api_data['label']}")
                            label_added = True
                except Exception as e:
                    print(f"Could not get label from API: {e}")
            
            # 2. Usar fuentes tradicionales si la API no funcionó
            if not label_added:
                if "LABEL_NAME" in song:
                    audio["ORGANIZATION"] = song["LABEL_NAME"]
                    audio["PUBLISHER"] = song["LABEL_NAME"]  # Campo adicional para Windows
                    #print(f"Added label from song: {song['LABEL_NAME']}")
                    label_added = True
                elif album_metadata and "LABEL_NAME" in album_metadata:
                    audio["ORGANIZATION"] = album_metadata["LABEL_NAME"]
                    audio["PUBLISHER"] = album_metadata["LABEL_NAME"]  # Campo adicional para Windows
                    #print(f"Added label from album metadata: {album_metadata['LABEL_NAME']}")
                    label_added = True
                    
            if not label_added:
                print("No label information found")
        except Exception as e:
            print(f"ERROR: Could not add label information: {e}")
        
        # Add cover art
                # Add cover art
        if "ALB_PICTURE" in song:
            try:
                picture_data = downloadpicture(song["ALB_PICTURE"])
                from mutagen.flac import Picture
                from PIL import Image
                import io
                
                # Convertir y redimensionar la imagen a 750x750 Baseline
                try:
                    # Convertir los bytes de la imagen a un objeto PIL
                    image = Image.open(io.BytesIO(picture_data))
                    
                    # Redimensionar a 750x750
                    image = image.resize((750, 750), Image.LANCZOS)
                    
                    # Guardar en formato JPEG Baseline (progressive=False)
                    output = io.BytesIO()
                    image.save(output, format='JPEG', quality=90, optimize=True, progressive=False)
                    picture_data = output.getvalue()
                    output.close()
                    #print("Image converted to 750x750 Baseline JPEG")
                except ImportError:
                    print("WARNING: PIL/Pillow not installed, using original image")
                except Exception as e:
                    print(f"WARNING: Could not resize image: {e}")
                
                # Crear correctamente el objeto Picture
                pic = Picture()
                pic.type = 3  # Cover (front)
                pic.mime = "image/jpeg"
                pic.desc = "Cover (Front)"
                pic.data = picture_data
                
                # Para Picture usamos las dimensiones actuales
                pic.width = 750
                pic.height = 750
                pic.depth = 24  # Color depth for JPEG
                
                # Add the picture to the FLAC file
                audio.add_picture(pic)
                #print("Added album cover (750x750 Baseline)")
            except Exception as e:
                print(f"ERROR: Could not add album cover to FLAC: {e}")
        
        # Asegurarnos de que los campos clave para Windows estén presentes
        if "release_date" in locals() and release_date:
            # Este campo es clave para que Windows muestre la fecha en propiedades
            audio["DATE"] = release_date
        
        # Save the changes
        audio.save()
        #print(f"Added Vorbis comments to FLAC file: {output_file}")


    except Exception as e:
        print(f"ERROR: Could not add Vorbis comments to FLAC: {e}")


def download_song(song: dict, output_file: str) -> None:
    # downloads and decrypts the song from Deezer. Adds ID3 and art cover
    # song: dict with information of the song (grabbed from Deezer.com)
    # output_file: absolute file name of the output file
    assert type(song) is dict, "song must be a dict"
    assert type(output_file) is str, "output_file must be a str"

    # Añadir un bloque para obtener datos del álbum si estamos en FLAC (para los metadatos completos)
    global album_Data
    is_flac = sound_format == "FLAC"
    
    # Si estamos descargando FLAC y no tenemos datos de álbum,
    # intentemos obtenerlos desde la canción primero
    if is_flac and ('album_Data' not in globals() or album_Data is None or "GENRES" not in album_Data):
        if "ALB_ID" in song:
            try:
                #print(f"Pre-fetching album data for better FLAC tags (album ID: {song['ALB_ID']})...")
                # Esto establecerá album_Data como efecto secundario
                album_songs = get_song_infos_from_deezer_website(TYPE_ALBUM, song['ALB_ID'])
                #print("Successfully fetched album data for better metadata")
            except Exception as e:
                print(f"WARNING: Could not pre-fetch album data: {e}")

    try:
        url = get_song_url(song["TRACK_TOKEN"])
    except Exception as e:
        print(f"Could not download song (https://www.deezer.com/us/track/{song['SNG_ID']}). Maybe it's not available anymore or at least not in your country. {e}")
        if "FALLBACK" in song:
            song = song["FALLBACK"]
            print(f"Trying fallback song https://www.deezer.com/us/track/{song['SNG_ID']}")
            try:
                url = get_song_url(song["TRACK_TOKEN"])
            except Exception:
                pass
            else:
                print("Fallback song seems to work")
        else:
            raise

    key = calcbfkey(song["SNG_ID"])
    try:
        with session.get(url, stream=True) as response:
            response.raise_for_status()
            with open(output_file, "w+b") as fo:
                # For MP3, use ID3 tags as before
                if not is_flac:
                    writeid3v2(fo, song)
                    decryptfile(response, key, fo)
                    writeid3v1_1(fo, song)
                else:
                    # For FLAC, just decrypt the file first
                    decryptfile(response, key, fo)
                    
        # For FLAC files, add Vorbis comments after the file is written
        if is_flac and os.path.exists(output_file):
            add_vorbis_tags(song, output_file)
        download_lrc(song["SNG_ID"], output_file)  # Llamar a la función de descarga de letras aquí

         
    

                    
    except Exception as e:
        raise DeezerApiException(f"Could not write song to disk: {e}") from e
    else:
        print("Download finished: {}".format(output_file))

# Definir album_Data globalmente al inicio del archivo (tras las importaciones)
album_Data = None

def download_lrc(track_id, output_file):
    """
    Download the lyrics for a given track ID and save them to a file.
    """
    try:
        lrc = get_lyrics_lrc(track_id) 
        if lrc:
            # Guardamos la letra en un archivo .lrc
            lrc_file = os.path.splitext(output_file)[0] + ".lrc"
            with open(lrc_file, "w", encoding="utf-8") as lrc_fo:
                lrc_fo.write(lrc)
            print(f"Lyrics saved to {lrc_file}")
    except Exception as e:
        print(f"WARNING: Could not get lyrics for song {track_id}: {e}")
    except requests.exceptions.RequestException as e:
        print(f"WARNING: Could not get lyrics for song {track_id}: {e}")



# MÉTODO ARREGLADO AQUÍ
def get_lyrics_lrc(track_id):
    updateCookies()
    global sessionJwt, tmp_jwt
    if sessionJwt is not None:


        url = "https://pipe.deezer.com/api"
        
        # La query de GraphQL debe ser una cadena limpia, sin comentarios de Python.
        # Los dobles saltos de línea (\n\n) entre la query principal y los fragments
        # son importantes y se mantienen.
        graphql_query = (
            "query GetLyrics($trackId: String!) {\n"
            "  track(trackId: $trackId) {\n"
            "    id\n"
            "    lyrics {\n"
            "      id\n"
            "      text\n"
            "      ...SynchronizedWordByWordLines\n"
            "      ...SynchronizedLines\n"
            "      copyright\n"
            "      writers\n"
            "      __typename\n"
            "    }\n"
            "    __typename\n"
            "  }\n"
            "}\n\n"  # Doble salto de línea
            "fragment SynchronizedWordByWordLines on Lyrics {\n"
            "  id\n"
            "  synchronizedWordByWordLines {\n"
            "    start\n"
            "    end\n"
            "    words {\n"
            "      start\n"
            "      end\n"
            "      word\n"
            "      __typename\n"
            "    }\n"
            "    __typename\n"
            "  }\n"
            "  __typename\n"
            "}\n\n"  # Doble salto de línea
            "fragment SynchronizedLines on Lyrics {\n"
            "  id\n"
            "  synchronizedLines {\n"
            "    lrcTimestamp\n"
            "    line\n"
            "    lineTranslated\n"
            "    milliseconds\n"
            "    duration\n"
            "    __typename\n"
            "  }\n"
            "  __typename\n"
            "}"
        )

        headers = {
            "Accept": "*/*",
            "Accept-Language": "es-ES",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36", # Coincide con tu request
            "Sec-Ch-Ua": "\"Not.A/Brand\";v=\"99\", \"Chromium\";v=\"136\"",
            "Sec-Ch-Ua-Platform": "\"Windows\"",
            "Sec-Ch-Ua-Mobile": "?0",
            "Content-Type": "application/json",
            "Origin": "https://www.deezer.com",
            "Referer": "https://www.deezer.com/",
            "Authorization": f"Bearer {tmp_jwt}",
            # Añadimos los headers Sec-Fetch-* que aparecen en tu request capturada
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            # "Priority: u=1, i" # Este es menos común que sea necesario, puedes probar con y sin él
        }

        payload = {
            "operationName": "GetLyrics",
            "variables": {"trackId": str(track_id)}, # Asegurarse que track_id es string
            "query": graphql_query,
        }

        try:
            # Hacemos una copia de la session pero SIN LAS COOKIES
            sessionAux = requests.Session()
            # Copiamos los headers de la sesión original

            r = sessionAux.post(url, json=payload, headers=headers, timeout=10)
            
            # Imprimir detalles para depuración, incluso si es exitoso al principio
            # print(f"--- Request a {url} ---")
            # print(f"Headers: {json.dumps(headers, indent=2)}")
            # print(f"Payload: {json.dumps(payload, indent=2)}")
            # print(f"Status Code: {r.status_code}")
            # print(f"Response Body: {r.text[:500]}...") # Imprime solo parte para no saturar

            r.raise_for_status() # Lanza excepción para errores HTTP 4xx/5xx

            data = r.json()
            
            # Navegación segura por el JSON
            track_data = data.get("data", {}).get("track")
            if not track_data:
                print(f"ERROR: No se encontró 'track' en la respuesta para ID {track_id}.", file=sys.stderr)
                print("Respuesta completa:", json.dumps(data, indent=2), file=sys.stderr)
                return "" # O podrías lanzar una excepción más específica

            lyrics_data = track_data.get("lyrics")
            if not lyrics_data:
                print(f"INFO: La canción con ID {track_id} no tiene datos de 'lyrics'.", file=sys.stderr)
                # Puede que la canción no tenga letra, o no sincronizada.
                return ""


            lines = lyrics_data.get("synchronizedLines")
            if not lines: # Si no hay synchronizedLines, la canción podría no tener letra o solo letra no sincronizada
                plain_text_lyrics = lyrics_data.get("text")
                if plain_text_lyrics:
                    print(f"INFO: No hay 'synchronizedLines' para ID {track_id}, pero sí texto plano.", file=sys.stderr)
                    # Devolver la letra como texto plano sin timestamps, o un LRC básico
                    lrc_lines = ["[offset:0]"]
                    for line_text in plain_text_lyrics.split('\n'):
                        if line_text.strip(): # Evitar líneas vacías
                            lrc_lines.append(f"[00:00.00]{line_text.strip()}")
                    return "\n".join(lrc_lines)
                else:
                    print(f"INFO: No hay 'synchronizedLines' ni 'text' para ID {track_id}.", file=sys.stderr)
                    return "[offset:0]\n(Letra no disponible)"


            return "\n".join(f"{ln['lrcTimestamp']}{ln['line']}" for ln in lines if ln.get('lrcTimestamp') and ln.get('line') is not None)

        except requests.exceptions.HTTPError as e:
            print(f"ERROR HTTP al pedir la letra: {e.response.status_code}", file=sys.stderr)
            print(f"URL: {e.request.url}", file=sys.stderr)
            print(f"Request headers: {json.dumps(dict(e.request.headers), indent=2)}", file=sys.stderr)
            if e.request.body:
                try:
                    print(f"Request body: {json.dumps(json.loads(e.request.body.decode()), indent=2)}", file=sys.stderr)
                except:
                    print(f"Request body (raw): {e.request.body.decode()}", file=sys.stderr)
            print(f"Response text: {e.response.text}", file=sys.stderr)
            return "" # O podrías relanzar la excepción: raise
        except requests.exceptions.RequestException as e:
            print(f"ERROR de red al pedir la letra: {e}", file=sys.stderr)
            return "" # O podrías relanzar: raise
        except json.JSONDecodeError:
            print("ERROR al decodificar JSON de la respuesta de letras.", file=sys.stderr)
            if 'r' in locals() and r: # si la variable r existe y tiene contenido
                print("Respuesta recibida:", r.text, file=sys.stderr)
            return "" # O podrías relanzar: raise
        except KeyError as e:
            print(f"ERROR: Falta la clave esperada '{e}' en la respuesta JSON de letras.", file=sys.stderr)
            if 'data' in locals() and data: # si la variable data existe y tiene contenido
                print("Estructura de datos recibida:", json.dumps(data, indent=2), file=sys.stderr)
            return "" # O podrías relanzar: raise



def get_song_infos_from_deezer_website(search_type, id):
    # Declarar como global al inicio de la función
    global album_Data
    
    url = "https://www.deezer.com/us/{}/{}".format(search_type, id)
    resp = session.get(url)
    if resp.status_code == 404:
        raise Deezer404Exception("ERROR: Got a 404 for {} from Deezer".format(url))
    if "MD5_ORIGIN" not in resp.text:
        raise Deezer403Exception("ERROR: we are not logged in on deezer.com. Please update the cookie")

    parser = ScriptExtractor()
    parser.feed(resp.text)
    parser.close()

    songs = []
    for script in parser.scripts:
        regex = re.search(r'{"DATA":.*', script)
        if regex:
            DZR_APP_STATE = json.loads(regex.group())
            album_Data = DZR_APP_STATE.get("DATA")
            
            # Intentar obtener el género si no está en los datos del álbum
            if album_Data and "GENRES" not in album_Data:
                # Intenta obtener género del artista si está disponible
                try:
                    if "ART_ID" in album_Data:
                        # También podríamos hacer una llamada adicional para obtener géneros
                        # del artista, pero eso requeriría una API extra
                        #print(f"No genre information found in album data, adding empty placeholder")
                        album_Data["GENRES"] = []  # Creamos un array vacío para evitar errores
                except Exception as e:
                    print(f"Could not get genre information: {e}")
            

            if "DATA" in DZR_APP_STATE:
                # Para playlists y álbumes, asegúrate de que cada canción tenga
                # la información básica del álbum para mejorar los metadatos
                if DZR_APP_STATE['DATA']['__TYPE__'] == 'playlist' or DZR_APP_STATE['DATA']['__TYPE__'] == 'album':
                    # Si estamos procesando una playlist, no usemos album_Data directamente
                    # ya que contiene datos de la playlist, no del álbum
                    is_playlist = DZR_APP_STATE['DATA']['__TYPE__'] == 'playlist'
                    
                    for song in DZR_APP_STATE['SONGS']['data']:
                        if is_playlist:
                            # Para cada canción en una playlist, obtenemos su álbum si es necesario
                            if "ALB_ID" in song and ("ORIGINAL_RELEASE_DATE" not in song or "GENRES" not in song):
                                try:
                                    #print(f"Fetching additional album data for song '{song.get('SNG_TITLE')}' (Album ID: {song['ALB_ID']})")
                                    # No usamos la variable global aquí para evitar sobrescribirla
                                    album_info = get_album_data(song['ALB_ID'])
                                    
                                    # Copia los datos relevantes del álbum a la canción
                                    if album_info:
                                        if "ORIGINAL_RELEASE_DATE" in album_info and "ORIGINAL_RELEASE_DATE" not in song:
                                            song["ORIGINAL_RELEASE_DATE"] = album_info["ORIGINAL_RELEASE_DATE"]
                                            #print(f"Added original release date: {album_info['ORIGINAL_RELEASE_DATE']}")
                                        if "PHYSICAL_RELEASE_DATE" in album_info and "PHYSICAL_RELEASE_DATE" not in song:
                                            song["PHYSICAL_RELEASE_DATE"] = album_info["PHYSICAL_RELEASE_DATE"]
                                        if "LABEL_NAME" in album_info and "LABEL_NAME" not in song:
                                            song["LABEL_NAME"] = album_info["LABEL_NAME"]
                                        if "GENRES" in album_info and album_info["GENRES"] and "GENRES" not in song:
                                            song["GENRES"] = album_info["GENRES"]
                                            if album_info["GENRES"]:
                                                genres = [g["name"] for g in album_info["GENRES"] if "name" in g]
                                except Exception as e:
                                    print(f"Error fetching album data for song: {e}")
                        else:
                            # Si es un álbum, usa los datos del álbum directamente
                            try:
                                if album_Data and "ORIGINAL_RELEASE_DATE" in album_Data and "ORIGINAL_RELEASE_DATE" not in song:
                                    song["ORIGINAL_RELEASE_DATE"] = album_Data["ORIGINAL_RELEASE_DATE"]
                                if album_Data and "PHYSICAL_RELEASE_DATE" in album_Data and "PHYSICAL_RELEASE_DATE" not in song:
                                    song["PHYSICAL_RELEASE_DATE"] = album_Data["PHYSICAL_RELEASE_DATE"]
                                if album_Data and "LABEL_NAME" in album_Data and "LABEL_NAME" not in song:
                                    song["LABEL_NAME"] = album_Data["LABEL_NAME"]
                                if album_Data and "GENRES" in album_Data and "GENRES" not in song:
                                    song["GENRES"] = album_Data["GENRES"]
                            except Exception as e:
                                print(f"Error copying album metadata to song: {e}")
                        songs.append(song)
                elif DZR_APP_STATE['DATA']['__TYPE__'] == 'song':
                    # Para canciones individuales, usa los datos del álbum disponibles
                    try:
                        song = DZR_APP_STATE['DATA']
                        if album_Data and "ORIGINAL_RELEASE_DATE" in album_Data and "ORIGINAL_RELEASE_DATE" not in song:
                            song["ORIGINAL_RELEASE_DATE"] = album_Data["ORIGINAL_RELEASE_DATE"]
                        if album_Data and "PHYSICAL_RELEASE_DATE" in album_Data and "PHYSICAL_RELEASE_DATE" not in song:
                            song["PHYSICAL_RELEASE_DATE"] = album_Data["PHYSICAL_RELEASE_DATE"]
                        if album_Data and "LABEL_NAME" in album_Data and "LABEL_NAME" not in song:
                            song["LABEL_NAME"] = album_Data["LABEL_NAME"]
                        if album_Data and "GENRES" in album_Data and "GENRES" not in song:
                            song["GENRES"] = album_Data["GENRES"]
                    except Exception as e:
                        print(f"Error copying album metadata to song: {e}")
                    songs.append(song)
            else:
                # Si solo se obtienen las canciones sin la estructura DATA completa
                if DZR_APP_STATE['DATA']['__TYPE__'] == 'playlist' or DZR_APP_STATE['DATA']['__TYPE__'] == 'album':
                    for song in DZR_APP_STATE['SONGS']['data']:
                        songs.append(song)
                elif DZR_APP_STATE['DATA']['__TYPE__'] == 'song':
                    songs.append(DZR_APP_STATE['DATA'])
    
    # Si procesamos un álbum, asegúrate de que album_Data contiene la información correcta
    if search_type == TYPE_ALBUM and DZR_APP_STATE.get("DATA"):
        album_Data = DZR_APP_STATE.get("DATA")
        
    return songs[0] if search_type == TYPE_TRACK else songs

# Agrega esta nueva función auxiliar para obtener datos del álbum sin afectar album_Data global
def get_album_data(album_id):
    """Obtiene datos del álbum sin modificar la variable global album_Data"""
    try:
        url = f"https://www.deezer.com/us/album/{album_id}"
        resp = session.get(url)
        if resp.status_code == 404:
            return None
        
        parser = ScriptExtractor()
        parser.feed(resp.text)
        parser.close()
        
        for script in parser.scripts:
            regex = re.search(r'{"DATA":.*', script)
            if regex:
                DZR_APP_STATE = json.loads(regex.group())
                if "DATA" in DZR_APP_STATE and DZR_APP_STATE["DATA"]["__TYPE__"] == "album":
                    return DZR_APP_STATE["DATA"]
    except Exception as e:
        print(f"Error fetching album data: {e}")
    
    return None



def get_album_metadata(album_id):
    """
    Obtiene metadatos completos de un álbum sin usar variables globales.
    
    Args:
        album_id: ID del álbum en Deezer
        
    Returns:
        dict: Diccionario con todos los metadatos del álbum o None si no se encuentra
    """
    try:
        url = f"https://www.deezer.com/us/album/{album_id}"
        resp = session.get(url)
        if resp.status_code == 404:
            print(f"Album ID {album_id} not found")
            return None
        
        parser = ScriptExtractor()
        parser.feed(resp.text)
        parser.close()
        
        for script in parser.scripts:
            regex = re.search(r'{"DATA":.*', script)
            if regex:
                DZR_APP_STATE = json.loads(regex.group())
                if "DATA" in DZR_APP_STATE and DZR_APP_STATE["DATA"]["__TYPE__"] == "album":
                    album_data = DZR_APP_STATE["DATA"]

                    # Guardamos los datos en un log para depuración

                    
                    # Añadir GENRES vacío si no existe
                    if "GENRES" not in album_data:
                        album_data["GENRES"] = []
                    
                    # Imprimir información útil para depuración
                    return album_data
                    
        print(f"No album data found for album ID {album_id}")
        return None
    except Exception as e:
        print(f"Error fetching album metadata: {e}")
        return None


def deezer_search(search, search_type):
    # search: string (What are you looking for?)
    # search_type: either one of the constants: TYPE_TRACK|TYPE_ALBUM|TYPE_ALBUM_TRACK (TYPE_PLAYLIST is not supported)
    # return: list of dicts (keys depend on search_type)

    if search_type not in [TYPE_TRACK, TYPE_ALBUM, TYPE_ALBUM_TRACK]:
        print("ERROR: search_type is wrong: {}".format(search_type))
        return []
    search = urllib.parse.quote_plus(search)
    try:
        if search_type == TYPE_ALBUM_TRACK:
            data = get_song_infos_from_deezer_website(TYPE_ALBUM, search)
        else:
            resp = session.get("https://api.deezer.com/search/{}?q={}".format(search_type, search))
            resp.raise_for_status()
            data = resp.json()
            data = data['data']
    except (requests.exceptions.RequestException, KeyError) as e:
        raise DeezerApiException(f"Could not search for track '{search}': {e}") from e
    return_nice = []
    for item in data:
        i = {}
        if search_type == TYPE_ALBUM:
            i['id'] = str(item['id'])
            i['id_type'] = TYPE_ALBUM
            i['album'] = item['title']
            i['album_id'] = item['id']
            i['img_url'] = item['cover_small']
            i['artist'] = item['artist']['name']
            i['title'] = ''
            i['preview_url'] = ''

        if search_type == TYPE_TRACK:
            i['id'] = str(item['id'])
            i['id_type'] = TYPE_TRACK
            i['title'] = item['title']
            i['img_url'] = item['album']['cover_small']
            i['album'] = item['album']['title']
            i['album_id'] = item['album']['id']
            i['artist'] = item['artist']['name']
            i['preview_url'] = item['preview']

        if search_type == TYPE_ALBUM_TRACK:
            i['id'] = str(item['SNG_ID'])
            i['id_type'] = TYPE_TRACK
            i['title'] = item['SNG_TITLE']
            i['img_url'] = '' # item['album']['cover_small']
            i['album'] = item['ALB_TITLE']
            i['album_id'] = item['ALB_ID']
            i['artist'] = item['ART_NAME']
            i['preview_url'] = next(media['HREF'] for media in item['MEDIA'] if media['TYPE'] == 'preview')

        return_nice.append(i)
    return return_nice


def parse_deezer_playlist(playlist_id):
    # playlist_id: id of the playlist or the url of it
    # e.g. https://www.deezer.com/de/playlist/6046721604 or 6046721604
    # return (playlist_name, list of songs) (song is a dict with information about the song)
    # raises DeezerApiException if something with the Deezer API is broken

    try:
        playlist_id = re.search(r'\d+', playlist_id).group(0)
    except AttributeError:
        raise DeezerApiException("ERROR: Regex (\\d+) for playlist_id failed. You gave me '{}'".format(playlist_id))

    url_get_csrf_token = "https://www.deezer.com/ajax/gw-light.php?method=deezer.getUserData&input=3&api_version=1.0&api_token="
    req = session.post(url_get_csrf_token)
    csrf_token = req.json()['results']['checkForm']

    url_get_playlist_songs = "https://www.deezer.com/ajax/gw-light.php?method=deezer.pagePlaylist&input=3&api_version=1.0&api_token={}".format(csrf_token)
    data = {'playlist_id': int(playlist_id),
            'start': 0,
            'tab': 0,
            'header': True,
            'lang': 'de',
            'nb': 500}
    req = session.post(url_get_playlist_songs, json=data)
    json = req.json()

    if len(json['error']) > 0:
        raise DeezerApiException("ERROR: deezer api said {}".format(json['error']))
    json_data = json['results']

    playlist_name = json_data['DATA']['TITLE']
    number_songs = json_data['DATA']['NB_SONG']
    print("Playlist '{}' has {} songs".format(playlist_name, number_songs))

    print("Got {} songs from API".format(json_data['SONGS']['count']))
    return playlist_name, json_data['SONGS']['data']


def get_deezer_favorites(user_id: str) -> Optional[Sequence[int]]:
    if not user_id.isnumeric():
        raise Exception(f"User id '{user_id}' must be numeric")
    resp = session.get(f"https://api.deezer.com/user/{user_id}/tracks?limit=10000000000")
    assert resp.status_code == 200, f"got invalid status asking for favorite song\n{resp.text}s"
    resp_json = resp.json()
    if "error" in resp_json.keys():
        raise Exception(f"Upstream api error getting favorite songs for user {user_id}:\n{resp_json['error']}")
    # check is set next

    while "next" in resp_json.keys():
        resp = session.get(resp_json["next"])
        assert resp.status_code == 200, f"got invalid status asking for favorite song\n{resp.text}s"
        resp_json_next = resp.json()
        if "error" in resp_json_next.keys():
            raise Exception(f"Upstream api error getting favorite songs for user {user_id}:\n{resp_json_next['error']}")
        resp_json["data"] += resp_json_next["data"]

        if "next" in resp_json_next.keys():
            resp_json["next"] = resp_json_next["next"]
        else:
            del resp_json["next"]

    print(f"Got {resp_json['total']} favorite songs for user {user_id} from the api")
    songs = [song['id'] for song in resp_json['data']]
    return songs


def test_deezer_login():
    print("Let's check if the deezer login is still working")
    try:
        song = get_song_infos_from_deezer_website(TYPE_TRACK, "917265")
    except (Deezer403Exception, Deezer404Exception) as msg:
        print(msg)
        print("Login is not working anymore.")
        return False

    if song:
        print("Login is still working.")
        return True
    else:
        print("Login is not working anymore.")
        return False


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "check-login":
        test_deezer_login()
