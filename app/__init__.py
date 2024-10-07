import os
import json
import re
from flask import Flask, request, abort, render_template
from app.config import DevConfig, ProdConfig
import time

from wakeonlan import send_magic_packet

from dotenv import load_dotenv

load_dotenv()

allowments = [
    r"^/\.well-known/",
    r"^/robots\.txt$",
    r"^/ads\.txt$",
    r"^/favicon\.ico$",
    r"^/sitemap\.xml",
    r"^/sitemap_index.xml",
]


def refresh_ban_list(data, ban_seconds=3600 * 24):
    """
    Refresh the IP ban list by removing expired entries.

    This function checks the 'ip_ban_list' in the input 'data' and removes any IPs
    where ban duration has passed.

    Args:
        data: A dictionary containing a list of the banned IPs,
            where each dictionary contains the IP address and the time the ban was added.
        ban_seconds (int, optional): The duration of the ban in seconds. Defaults to 24 hours (3600 * 24).

    Returns:
        The updated data with expired bans removed.

    Raises:
        KeyError: If the 'ip_ban_list' key is not found in 'data'.
    """

    data["ip_ban_list"] = [
        item
        for item in data["ip_ban_list"]
        if item["time_added"] + ban_seconds > int(time.time())
    ]
    return data


def check_ip(ip: str, data):
    """
    Check if an IP address exists in the ban list and update it.

    This function searches for the given 'ip' in the 'ip_ban_list'. If found, it increments
    the 'unauthorized_requests' counter and updates the 'time_added' to the current time.
    If the 'ip' is not found, a new entry is added to the list.

    Args:
        ip (str): The IP address to check.
        data: A dictionary containing a list of the banned IPs,
            where each dictionary contains the IP address and the time the ban was added.

    Returns:
        The updated data with the modified or newly added IP ban entry.

    Raises:
        KeyError: If the 'ip_ban_list' key is not found in 'data'.
    """

    for item in data["ip_ban_list"]:
        if ip == item["ip"]:
            item["unautorized_requests"] += 1
            item["time_added"] = int(time.time())
            break
    else:
        data["ip_ban_list"].append(
            {"ip": ip, "unautorized_requests": 1, "time_added": int(time.time())}
        )

    return data


def update_data_file(data_file: str, data: list[dict[str, str | int]]) -> None:
    """
    Update a data file by writing the provided data in JSON format.
    """

    with open(data_file, "w") as file:
        json.dump(data, file)


data = {"ip_ban_list": [], "mac_address": ""}


def create_app(data_file="data.json", ban_count=5) -> Flask:
    global data

    if os.path.isfile(data_file):
        with open(data_file) as file:
            data = json.load(file)
    else:
        with open(data_file, "x") as file:
            json.dump(data, file)

    # create and configure the app
    app = Flask(__name__)

    app.config.from_object(DevConfig if os.environ.get("FLASK_DEBUG") else ProdConfig)

    @app.route("/")
    def index():
        return render_template("index.html", mac=data["mac_address"])

    # wakeup api
    @app.route("/wake", methods=["POST"])
    def wake():
        global data

        response_body = json.loads(request.data)
        data["mac_address"] = response_body["mac"]
        update_data_file(data_file, data)
        password = response_body["password"]

        if password != os.environ.get("PASSWORD"):
            ip = request.environ.get("REMOTE_ADDR")
            data = check_ip(ip, data)
            update_data_file(data_file, data)
            return {"message": "Wrong password."}, 403

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
        global data

        if not (
            True
            in [
                re.match(allowment, request.path) is not None
                for allowment in allowments
            ]
        ):
            ip = request.environ.get("REMOTE_ADDR")
            data = check_ip(ip, data)
            update_data_file(data_file, data)

        return {"message": "This route does not exist"}, 404

    @app.errorhandler(403)
    def forbidden(error):
        return {"message": "Fuck off!"}, 403

    @app.before_request
    def block_method():
        global data

        # refresh the ban list
        data = refresh_ban_list(data)
        update_data_file(data_file, data)

        # do not allow if ip is banned
        ip = request.environ.get("REMOTE_ADDR")
        for item in data["ip_ban_list"]:
            if ip == item["ip"] and item["unautorized_requests"] >= ban_count:
                item["unautorized_requests"] += 1
                item["time_added"] = int(time.time())
                update_data_file(data_file, data)
                abort(403)

    return app
