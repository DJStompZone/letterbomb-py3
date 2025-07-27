import os
import zipfile
import hashlib
import hmac
import struct
import logging
import json
from io import BytesIO
from datetime import datetime, timedelta

from flask import (
    Flask, request, g, render_template, make_response, has_request_context
)
from logging.handlers import SMTPHandler
import requests

# --- Constants ---
GEOIP_DB_PATH = '/usr/share/GeoIP/GeoLite2-Country.mmdb'
OUI_LIST_FILE = 'oui_list.txt'
COUNTRY_REGIONS_FILE = 'country_regions.txt'
BUNDLE_DIRNAME = 'bundle'
EXPLOIT_FILENAME = 'LetterBomb.zip'
TEMPLATE_FILENAMES = {
    'U': "templateU.bin",
    'E': "templateE.bin",
    'J': "templateJ.bin",
    'K': "templateK.bin",
}
DOLPHIN_DERP_MAC = b"\x00\x17\xab\x99\x99\x99"
BOMB_PATH_TEMPLATE = (
    "private/wii/title/HAEA/"
    "{key0}/{key1}/{year:04d}/{month:02d}/{day:02d}/{hour:02d}/{minute:02d}/"
    "HABA_#1/txt/{timestamp:08X}.000"
)

# --- Flask Setup ---
app = Flask(__name__)
app.config.from_object("config")
BUNDLEBASE = os.path.join(app.root_path, BUNDLE_DIRNAME)

# --- Load Country Region Mapping ---
with open(os.path.join(app.root_path, COUNTRY_REGIONS_FILE)) as f:
    COUNTRY_REGIONS = dict(
        line.strip().split(" ") for line in f if line.strip()
    )

# --- GeoIP ---
try:
    import geoip2.database
    import geoip2.errors
    gi = geoip2.database.Reader(GEOIP_DB_PATH)
except ImportError:
    gi = None

# --- Logging ---
class RequestFormatter(logging.Formatter):
    def format(self, record):
        s = super().format(record)
        if has_request_context():
            return f"[{self.formatTime(record)}] [{request.remote_addr}] [{request.method} {request.path}] {s}"
        return f"[{self.formatTime(record)}] [SYS] {s}"

if not app.debug:
    mail_handler = SMTPHandler(
        app.config['SMTP_SERVER'],
        app.config['APP_EMAIL'],
        app.config['ADMIN_EMAIL'],
        'LetterBomb ERROR'
    )
    mail_handler.setLevel(logging.ERROR)
    app.logger.addHandler(mail_handler)

    file_handler = logging.FileHandler(os.path.join(app.root_path, 'log', 'info.log'))
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(RequestFormatter())
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.warning('Starting...')

# --- Context Processor ---
@app.context_processor
def inject_globals():
    return {
        "recaptcha_key": app.config['RECAPTCHA_PUBLICKEY']
    }

# --- Region Lookup ---
def region():
    if gi is None:
        return 'E'
    try:
        country = gi.country(request.remote_addr).country.iso_code
        app.logger.info(f"GeoIP: {request.remote_addr} → {country}")
        return COUNTRY_REGIONS.get(country, 'E')
    except geoip2.errors.AddressNotFoundError:
        return 'E'
    except Exception:
        app.logger.exception("GeoIP lookup failed")
        return 'E'

# --- CAPTCHA Verification ---
def captcha_check():
    try:
        payload = {
            "secret": app.config['RECAPTCHA_PRIVATEKEY'],
            "response": request.form.get('g-recaptcha-response'),
            "remoteip": request.remote_addr
        }
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
        result = r.json()
        if not result.get("success"):
            app.logger.info(f"ReCAPTCHA failure: {result}")
            return False
        return True
    except Exception:
        app.logger.exception("CAPTCHA check failed")
        return False

# --- Main Route ---
@app.route('/')
def index():
    return render_template('index.html', region=region())

# --- Exploit Route ---
@app.route('/haxx', methods=["POST"])
def haxx():
    with open(os.path.join(app.root_path, OUI_LIST_FILE)) as f:
        OUI_LIST = [bytes.fromhex(line.strip()) for line in f if len(line.strip()) == 6]

    dt = datetime.utcnow() - timedelta(days=1)
    timestamp = int((dt - datetime(2000, 1, 1)).total_seconds())

    try:
        mac = bytes(int(request.form[i], 16) for i in "abcdef")
        region_code = request.form['region']
        template_filename = TEMPLATE_FILENAMES[region_code]
        want_bundle = 'bundle' in request.form
    except Exception:
        return render_template("index.html", region=region(), error="Invalid input.")

    if not captcha_check():
        return render_template("index.html", region=region(), error="Are you a human?")

    if mac == DOLPHIN_DERP_MAC:
        app.logger.info(f"Derp MAC {mac.hex()} @ {timestamp} [{region_code}] bundle={want_bundle}")
        return render_template("index.html", region=region(), error="If you're using Dolphin, try File → Open instead ;)")

    if not any(mac.startswith(oui) for oui in OUI_LIST):
        app.logger.info(f"Invalid MAC {mac.hex()} @ {timestamp} [{region_code}] bundle={want_bundle}")
        return render_template("index.html", region=region(), error="The exploit will only work if you enter your Wii's MAC address.")

    key = hashlib.sha1(mac + b"uyy").digest()

    with open(os.path.join(app.root_path, template_filename), 'rb') as f:
        blob = bytearray(f.read())

    blob[0x08:0x10] = key[:8]
    blob[0xb0:0xc4] = bytes(20)
    blob[0x7c:0x80] = struct.pack(">I", timestamp)
    blob[0x80:0x8a] = f"{timestamp:010d}".encode()
    blob[0xb0:0xc4] = hmac.new(key[8:], blob, hashlib.sha1).digest()

    zip_path = BOMB_PATH_TEMPLATE.format(
        key0=key[:4].hex().upper(),
        key1=key[4:8].hex().upper(),
        year=dt.year,
        month=dt.month - 1,
        day=dt.day,
        hour=dt.hour,
        minute=dt.minute,
        timestamp=timestamp
    )

    zip_data = BytesIO()
    with zipfile.ZipFile(zip_data, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(zip_path, blob)
        if want_bundle:
            for name in os.listdir(BUNDLEBASE):
                if not name.startswith("."):
                    z.write(os.path.join(BUNDLEBASE, name), name)

    app.logger.info(f"LetterBombed {mac.hex()} @ {timestamp} [{region_code}] bundle={want_bundle}")

    rs = make_response(zip_data.getvalue())
    rs.headers['Content-Disposition'] = f'attachment; filename={EXPLOIT_FILENAME}'
    rs.headers['Content-Type'] = 'application/zip'
    rs.headers['Expires'] = 'Thu, 01 Dec 1983 20:00:00 GMT'
    return rs

# --- WSGI Entry Point ---
application = app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10142)
