import logging
import os
import ssl
from dataclasses import dataclass

import azure.functions as func
from azure.functions import HttpMethod
from sslpsk3 import wrap_socket
from zabbix_utils import Sender

# env var names
ZABBIX_SERVER_HOST = "ZABBIX_SERVER_HOST"
ZABBIX_PSK_SECRET = "ZABBIX_PSK_SECRET"
ZABBIX_PSK_IDENTITY = "ZABBIX_PSK_IDENTITY"


@dataclass
class ZabbixRequest:
    host: str
    key: str
    value: str

def psk_wrapper(sock, _):
    psk = bytes.fromhex(os.environ.get(ZABBIX_PSK_SECRET))
    psk_identity = os.environ.get(ZABBIX_PSK_IDENTITY).encode('utf-8')

    if psk and psk_identity:
        return wrap_socket(
            sock,
            ssl_version=ssl.PROTOCOL_TLSv1_2,
            ciphers='ECDHE-PSK-AES128-CBC-SHA256',
            psk=(psk, psk_identity)
        )

    return sock


app = func.FunctionApp()


@app.route(route="ZabbixSend", methods=[HttpMethod.POST], auth_level=func.AuthLevel.FUNCTION)
def ZabbixSend(req: func.HttpRequest) -> func.HttpResponse:
    zabbix_server = os.environ.get(ZABBIX_SERVER_HOST)

    body_dict = req.get_json()

    if not body_dict:
        return func.HttpResponse("Must provide body:{\"host\": \"str\", \"key\": \"str\", \"value\": \"str\",}.",
                                 status_code=400)

    body = ZabbixRequest(**body_dict)

    sender = Sender(server=zabbix_server, socket_wrapper=psk_wrapper)

    try:
        response = sender.send_value(body.host, body.key, body.value)
    except Exception as e:
        return func.HttpResponse(f"Failed to send value: {e}", status_code=500)

    if response.failed == 0:
        return func.HttpResponse(f"Value sent successfully in {response.time}", status_code=200)
    elif response.details:
        for node, chunks in response.details.items():
            for resp in chunks:
                if resp.failed == 0:
                    logging.info(f"Value sent successfully to {node} in {resp.time}")
                else:
                    logging.error(f"Failed to send value to {node} at chunk step {resp.chunk}")

        return func.HttpResponse(f"Values sent {response.processed}/{response.total}", status_code=200)
    else:
        return func.HttpResponse("Failed to send value:", status_code=500)
