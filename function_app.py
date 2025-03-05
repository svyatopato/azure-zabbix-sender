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
class ZabbixArgs:
    host: str
    key: str
    value: str

    def __post_init__(self):
        if self.host is None:
            raise ValueError("customProperties.host cannot be null!")

        if self.key is None:
            raise ValueError("customProperties.key cannot be null!")

        if self.value is None:
            raise ValueError("customProperties.value cannot be null!")


@dataclass
class CustomProperties:
    customProperties: ZabbixArgs

    def __post_init__(self):
        if self.customProperties is None:
            raise ValueError("customProperties cannot be null!")


@dataclass
class AlertRequest:
    data: CustomProperties


def parse_json(body_dict: dict) -> AlertRequest:
    if not body_dict:
        raise ValueError("body is missing")

    return AlertRequest(
        data=CustomProperties(
            customProperties=ZabbixArgs(**body_dict.get("data", {}).get("customProperties", {}))
        )
    )


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

    try:
        body = parse_json(body_dict)
    except ValueError as e:
        return func.HttpResponse(f"Invalid body: {e}", status_code=400)

    sender = Sender(server=zabbix_server, socket_wrapper=psk_wrapper)

    host = body.data.customProperties.host
    key = body.data.customProperties.key
    value = body.data.customProperties.value

    try:
        response = sender.send_value(host, key, value)
    except Exception as e:
        logging.error(f"Failed to send value to zabbix(host: {host}, key: {key}, value: {value}): {e}")
        return func.HttpResponse(f"Error occurred while sending data to Zabbix", status_code=500)

    if response.failed == 0:
        return func.HttpResponse(f"Value sent successfully in {response.time}", status_code=200)
    elif response.details:
        for node, chunks in response.details.items():
            for resp in chunks:
                if resp.failed == 0:
                    logging.debug(f"Value sent successfully to {node} in {resp.time}")
                else:
                    logging.warning(f"Failed to send value to {node} at chunk step {resp.chunk}")

        return func.HttpResponse(f"Values sent {response.processed}/{response.total}", status_code=200)
    else:
        return func.HttpResponse("Request has been sent. But error occurred during processing", status_code=500)
