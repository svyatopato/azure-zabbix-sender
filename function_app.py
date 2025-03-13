import logging
import os
import ssl

import azure.functions as func
from azure.functions import HttpMethod
from jsonschema.exceptions import ValidationError
from sslpsk3 import wrap_socket
from zabbix_utils import Sender
from jsonschema import validate

# env var names
ZABBIX_SERVER_HOST = "ZABBIX_SERVER_HOST"
ZABBIX_PSK_SECRET = "ZABBIX_PSK_SECRET"
ZABBIX_PSK_IDENTITY = "ZABBIX_PSK_IDENTITY"

schema = {
    "type": "object",
    "properties": {
        "data": {
            "type": "object",
            "properties": {
                "essentials": {
                    "type": "object",
                    "properties": {
                        "description": {"type": "string"}
                    },
                    "required": ["description"]
                },
                "customProperties": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "key": {"type": "string"}
                    },
                    "required": ["host", "key"]
                }
            },
            "required": ["essentials", "customProperties"]
        }
    },
    "required": ["data"]
}


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

    body = req.get_json()

    if not body:
        return func.HttpResponse("Body must not be empty", status_code=400)


    try:
        validate(body, schema)
    except ValidationError as e:
        response_object = {
            "status": "400",
            "message": "Validation failed",
            "error": e.message,
            "path": list(e.path),
            "schema_path": list(e.schema_path)
        }
        return func.HttpResponse(f"{response_object}", status_code=400)

    sender = Sender(server=zabbix_server, socket_wrapper=psk_wrapper)

    host = body.get("data", {}).get("customProperties", {}).get("host")
    key = body.get("data", {}).get("customProperties", {}).get("key")
    value = body.get("data", {}).get("essentials", {}).get("description")

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
