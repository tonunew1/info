
import asyncio
import time
import httpx
import json
import threading
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB51"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = {}

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials() -> str:
    # শুধু BD এর UID + password
    return "uid=4198040669&password=BD19CBC961423CF5E2A006920242703DAE4F5F7607BC37D52A0E54F96927D46E"

# === Token Generation ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt():
    account = get_account_credentials()
    token_val, open_id = await get_access_token(account)
    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    })
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        if resp.status_code != 200 or not resp.content or resp.content.startswith(b'BR_GOP_TOKEN_AUTH_FAILED'):
            raise RuntimeError("Token request failed")
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))

        cached_tokens["BD"] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200  # 7 hours
        }

async def get_token_info() -> Tuple[str, str, str]:
    info = cached_tokens.get("BD")
    if not info or time.time() >= info['expires_at']:
        await create_jwt()
        info = cached_tokens["BD"]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, endpoint):
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info()
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(server+endpoint, data=data_enc, headers=headers)
        if resp.status_code == 401:  # token expired
            await create_jwt()
            return await GetAccountInformation(uid, unk, endpoint)
        return json.loads(json_format.MessageToJson(
            decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
        ))

# === Caching Decorator ===
def cached_endpoint(ttl=300):
    def decorator(fn):
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# === Flask Routes ===
@app.route('/player-info')
@cached_endpoint()
def get_account_info():
    uid = request.args.get('uid')

    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    try:
        return_data = asyncio.run(GetAccountInformation(uid, "7", "/GetPlayerPersonalShow"))
        formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
        return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}

    except Exception as e:
        return jsonify({"error": f"Failed to fetch info: {e}"}), 500

@app.route("/")
def home():
    return jsonify({
        "Credits": "Dev By Mustakin",
        "region": "BD Only",
        "auto_refresh": "Every 7 hours"
    })

# === Auto Refresh Background Task ===
def schedule_token_refresh():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def refresh_forever():
        while True:
            try:
                await create_jwt()
                print("✅ Token auto-refreshed for BD")
            except Exception as e:
                print(f"❌ Auto-refresh failed: {e}")
            await asyncio.sleep(25200)  # 7 hours

    loop.run_until_complete(refresh_forever())

# === Startup ===
async def startup():
    await create_jwt()

if __name__ == '__main__':
    # প্রথমবার token তৈরি
    asyncio.run(startup())

    # Background auto-refresh চালু
    t = threading.Thread(target=schedule_token_refresh, daemon=True)
    t.start()

    # Flask চালু
    app.run(host='0.0.0.0', port=5000, debug=True)


