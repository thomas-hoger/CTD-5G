import json
import re
from urllib.parse import parse_qs, urlparse

import jwt
from pyshark.packet.packet import Packet

http_type = {
    0: "DATA",
    1: "HEADERS",
    2: "PRIORITY",
    3: "RST_STREAM",
    4: "SETTINGS",
    5: "PUSH_PROMISE",
    6: "PING",
    7: "GOAWAY",
    8: "WINDOW_UPDATE",
    9: "CONTINUATION"
}

def decode_jwt(token: str) -> dict:
    """
    Decodes a JSON Web Token (JWT) and returns its header and content.
    Args:
        token (str): The JWT string, typically prefixed with "Bearer ".
    Returns:
        dict: A dictionary containing the decoded header and content of the JWT.
    """
    token = token.replace("Bearer ", "")
    if token.startswith("eyJ"):
        header = jwt.get_unverified_header(token)
        content = jwt.decode(token, options={"verify_signature": False})
        return header | content
    return {}

def parse_urlencoded_params(url: str) -> dict:
    result = {}
    parsed_url = urlparse(url)
    result['path'] = parsed_url.path

    # get the param of the url
    if parsed_url.query:
        parsed_query = parse_qs(parsed_url.query)

        for key, values in parsed_query.items():
            new_values = []
            for value in values:
                try:
                    new_value = json.loads(value)
                    new_values.append(new_value)
                except json.JSONDecodeError:
                    new_values.append(value)

            if len(new_values) == 1:
                result[key] = new_values[0]

    # remove the parameters from the path variable
    result['path'] = result['path'].split("?")[0]

    pattern_to_replace = {
        "nfInstanceId" : r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        "subToNotify"  : r"subs-to-notify/([^/?]+)"
    }

    # Regex pattern for UUID of the shape "bc60cde2-eaed-45fc-9d01-79d1054eec12"
    for key, pattern in pattern_to_replace.items():
        match = re.search(pattern, result['path'])
        if match:
            value = match.group(0)
            result[key] = value
            result['path'] = result['path'].replace(value, key)

    return result

def extract_json(data: str) -> dict:
    try:
        loaded = json.loads(data)
        if isinstance(loaded, list):
            loaded = {index: value for index, value in enumerate(loaded)}

        if loaded is not None:
            return loaded
        else:
            return {}
    except Exception:
        return {}

def extract_json_mime(packet: Packet) -> dict:
    if hasattr(packet.http2, 'json_object'):
        json_data = packet.http2.json_object
        json_dict = json.loads(json_data)
        return json_dict
    return {}

def field_unpacking(field: str, pkt_json_content: dict) -> dict:
    """If an HTTP packet contain a certain field it must be further jsonified.
        May be replacable by a function that jsonify recursively the content.

    Args:
        field (str) : Name of the field to unpack
        pkt_json_content (PacketJson): Packet dissected that need further processing
    Returns:
        PacketJson: Processed dissected packet
    """
    field_content = pkt_json_content[field]
    if isinstance(field_content, list) and len(field_content) == 1:
        field_content = field_content[0]

    try:
        field_content = json.loads(field_content)

        if field_content:
            if isinstance(field_content, list):
                for value in field_content:
                    pkt_json_content.update(value)
            else:
                pkt_json_content.update(field_content)

    # A field can sometimes need an unpacking and sometimes don't
    # So if it doesn't we dont want to delete it after
    except ValueError:
        new_field_name = f"{field}_unpacked"
        pkt_json_content.update({new_field_name: field_content})

    return pkt_json_content

def dissect_http2(packet: Packet) -> list:  # noqa: PLR0912
    """Dissect HTTP2 Frame packet

    Args:
        pkt (Packet): Pyshark packet that will be dissected
    Returns:
        dict: Extracted features and their values
    """
    dissected_layers = []

    for layer in packet.layers:
        if layer.layer_name == 'http2':
            fields = layer._all_fields
            if "http2.type" in fields:
                fields["http2.type"] = http_type[int(fields["http2.type"])]
                content = {}

                if fields["http2.type"] == "DATA":

                    try:
                        data = layer.get("http2.data.data").binary_value.decode('UTF8', 'replace')
                        content.update(extract_json(data))
                        content.update(extract_json_mime(packet))
                    except Exception:
                        pass

                elif fields["http2.type"] == "HEADERS":
                    for key, val in fields.items():
                        for field in ["status", "path", "method", "authorization"]:
                            if f"headers.{field}" in key:
                                if field != "path":
                                    content[field] = val
                                else:
                                    url_decoded = parse_urlencoded_params(val)
                                    content.update(url_decoded)

                # Decipher the jwt
                if content:
                    for jwt_key in ["access_token", "authorization"]:
                        if jwt_key in content:
                            jwt_raw = content.pop(jwt_key)
                            if isinstance(jwt_raw, list):
                                jwt_raw = jwt_raw[0]
                            content["jwt"] = decode_jwt(jwt_raw)

                    # Flags
                    if 'http2.flags.end_stream' in fields:
                        content["stream_response"] = str(fields['http2.flags.end_stream']) == "True"
                        content["stream_id"] = int(fields['http2.streamid'])

                    dissected_layers.append(content)

    return dissected_layers
