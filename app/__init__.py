import os
import json
import re
import time
from flask import Flask, request, abort
from flask_ipban import IpBan
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import DevConfig, ProdConfig

from wakeonlan import send_magic_packet

from dotenv import load_dotenv

load_dotenv()


data = {"mac_address": ""}


def create_app(data_file="data.json") -> Flask:
    global data

    if os.path.isfile(data_file):
        with open(data_file) as file:
            data = json.load(file)
    else:
        with open(data_file, "x") as file:
            json.dump(data, file)

    # create and configure the app
    app = Flask(__name__, static_url_path="")
    # proxy fix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # ipban for security
    os.makedirs("records", exist_ok=True)
    ip_ban = IpBan(app, ban_count=10, persist=True, record_dir="records")
    ip_ban.ip_whitelist_add("127.0.0.1")

    app.config.from_object(DevConfig if os.environ.get("FLASK_DEBUG") else ProdConfig)

    @app.route("/")
    def index():
        return app.send_static_file("index.html")

    # wakeup api
    @app.route("/wake", methods=["POST"])
    def wake():
        global data

        # get the response data
        response_body = json.loads(request.data)

        # stop here, if the password was wrong
        if response_body["password"] != os.environ.get("PASSWORD"):
            ip_ban.add()
            return {"message": "Wrong password"}, 403

        # get mac address
        if response_body["mac"]:
            # update the data and write it to disk
            data["mac_address"] = response_body["mac"]
            with open(data_file, "w") as file:
                json.dump(data, file)

        try:
            if not data["mac_address"]:
                raise RuntimeError("Mac address has to be set before wakeup")

            print(f"waking up {data["mac_address"]}")
            send_magic_packet(data["mac_address"])
        except Exception as e:
            return {"message": str(e)}, 501

        return {"message": "OK"}, 200

    @app.errorhandler(404)
    def not_found(error):
        return {"message": "This route does not exist"}, 404

    @app.errorhandler(403)
    def forbidden(error):
        return {"message": "Fuck off!"}, 403

    return app
