import asyncio
import time
import httpx
import json
import os
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
from Crypto.Util.Padding import pad # Added this import

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

# New key and IV for encrypt_api from the provided script
ENCRYPT_API_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
ENCRYPT_API_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

RELEASEVERSION = "OB51"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"PK", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "IND", "CIS", "BD", "EU"}
REGION_LANG = {"ME": "ar","IND": "hi","ID": "id","VN": "vi","TH": "th","BD": "bn","PK": "ur","TW": "zh","CIS": "ru","SAC": "es","BR": "pt", "SG": "en"}

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# === Helper Functions ===
def _custom_pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(_custom_pad(plaintext))

def encrypt_api(plain_text_hex):
    plain_text = bytes.fromhex(plain_text_hex)
    cipher = AES.new(ENCRYPT_API_KEY, AES.MODE_CBC, ENCRYPT_API_IV)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "PK":
        return "uid=4017149174&password=754NCUB3ZYJNAX1OI24BR9BGHFS5L1046841MFDDQ9CMME9N1Q846R2X27KN49NH"
    elif r == "IND":
        return "uid=4288511979&password=I_6ZSU8_BY_SPIDEERIO_GAMING_K2BWU"
    elif r == "EUROPE":
        return "uid=4147772370&password=8D6F0E27FEEB565E43B8EBE9BFDB3007F18B00D81E8F33269D840C97667C9AB5"
    elif r == "ME":
        return "uid=4260531157&password=saeedxmotoxkaka_J7FAA5VUJ1H"
    elif r == "ID":
        return "uid=4260534584&password=saeedxmotoxkaka_HDKG6UAIFDC"
    elif r == "TH":
        return "uid=4260538360&password=saeedxmotoxkaka_0RAJK56TTWT"
    elif r in {"VN", "VI"}:
        return "uid=4260542161&password=saeedxmotoxkaka_ARLN3LDW3JZ"
    elif r == "SG":
        return "uid=3158350464&password=70EA041FCF79190E3D0A8F3CA95CAAE1F39782696CE9D85C2CCD525E28D223FC"
    elif r == "BD":
        return "uid=4260559999&password=saeedxmotoxkaka_3PJ4Z1XNC3Q"
    elif r == "RU":
        return "uid=3309128798&password=412F68B618A8FAEDCCE289121AC4695C0046D2E45DB07EE512B4B3516DDA8B0F"
    else:
        return "uid=3158350464&password=70EA041FCF79190E3D0A8F3CA95CAAE1F39782696CE9D85C2CCD525E28D223FC"

def get_server_url(region: str) -> str:
    r = region.upper()
    if r in {"PK", "EU", "ID", "TH", "VN", "VI", "SG", "BD", "RU", "ME"}:
        return "https://clientbp.ggblueshark.com"
    elif r == "IND":
        return "https://client.ind.freefiremobile.com"
    elif r in {"BR", "US", "NA"}:
        return "https://client.us.freefiremobile.com"
    else:
        return "https://clientbp.ggblueshark.com"

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers, timeout=30)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)

    # Constructing the complex payload similar to the provided script
    payload_parts = [
        b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
        REGION_LANG.get(region.upper(), "en").encode("ascii"), # Use region's language
        b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
    ]

    raw_payload = b''.join(payload_parts)
    raw_payload = raw_payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', token_val.encode())
    raw_payload = raw_payload.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())

    final_payload = bytes.fromhex(encrypt_api(raw_payload.hex()))

    url = get_server_url(region) + "/MajorLogin"
    headers = {
        'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=final_payload, headers=headers, timeout=30)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': get_server_url(region),
            'expires_at': time.time() + 25200
        }

async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    headers = {
        'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 'Expect': "100-continue",
        'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

def format_response(data):
    return {
        "AccountInfo": {
            "AccountName": data.get("basicInfo", {}).get("nickname"),
            "AccountLevel": data.get("basicInfo", {}).get("level"),
            "AccountEXP": data.get("basicInfo", {}).get("exp"),
            "AccountRegion": data.get("basicInfo", {}).get("region"),
            "AccountLikes": data.get("basicInfo", {}).get("liked"),
            "AccountLastLogin": data.get("basicInfo", {}).get("lastLoginAt"),
            "AccountCreateTime": data.get("basicInfo", {}).get("createAt"),
            "AccountSeasonId": data.get("basicInfo", {}).get("seasonId"),
        },
        "AccountProfileInfo": {
            "BrMaxRank": data.get("basicInfo", {}).get("maxRank"),
            "BrRankPoint": data.get("basicInfo", {}).get("rankingPoints"),
            "CsMaxRank": data.get("basicInfo", {}).get("csMaxRank"),
            "CsRankPoint": data.get("basicInfo", {}).get("csRankingPoints"),
            "ShowBrRank": data.get("basicInfo", {}).get("showBrRank"),
            "ShowCsRank": data.get("basicInfo", {}).get("showCsRank"),
            "Title": data.get("basicInfo", {}).get("title")
        },
        "EquippedItemsInfo": {
            "EquippedAvatarId": data.get("basicInfo", {}).get("headPic"),
            "EquippedBPBadges": data.get("basicInfo", {}).get("badgeCnt"),
            "EquippedBPID": data.get("basicInfo", {}).get("badgeId"),
            "EquippedBannerId": data.get("basicInfo", {}).get("bannerId"),
            "EquippedOutfit": data.get("profileInfo", {}).get("clothes", []),
            "EquippedWeapon": data.get("basicInfo", {}).get("weaponSkinShows", []),
            "EquippedSkills": data.get("profileInfo", {}).get("equipedSkills", [])
        },
        "SocialInfo": data.get("socialInfo", {}),
        "PetInfo": data.get("petInfo", {}),
        "AccountType": data.get("basicInfo", {}).get("accountType"),
        "ReleaseVersion": data.get("basicInfo", {}).get("releaseVersion"),
        "CreditScoreInfo": data.get("creditScoreInfo", {}),
        "GuildInfo": {
            "GuildCapacity": data.get("clanBasicInfo", {}).get("capacity"),
            "GuildID": str(data.get("clanBasicInfo", {}).get("clanId")),
            "GuildLevel": data.get("clanBasicInfo", {}).get("clanLevel"),
            "GuildMember": data.get("clanBasicInfo", {}).get("memberNum"),
            "GuildName": data.get("clanBasicInfo", {}).get("clanName"),
            "GuildOwner": str(data.get("clanBasicInfo", {}).get("captainId"))
        },
        "GuildOwnerInfo": data.get("captainBasicInfo", {})
    }

# === API Routes ===
@app.route('/get')
async def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    
    try:
        region = request.args.get('region', 'PK').upper() # Default to PK if not provided
        
        # Get account information
        return_data = await GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
        formatted = format_response(return_data)
        return jsonify(formatted), 200
    
    except Exception as e:
        return jsonify({"error": "Invalid UID or server error. Please try again."}), 500

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message': 'Tokens refreshed for all regions.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

# === Startup ===
async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup())
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
    
    
#THIS CODE CREATE BY @Saeedxdie
#THIS CODE CREATE BY @Saeedxdie
#THIS CODE CREATE BY @Saeedxdie
