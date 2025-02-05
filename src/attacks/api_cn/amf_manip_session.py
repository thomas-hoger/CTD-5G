from src import *
import httpx
import uuid
import json

def json_to_multipart_bytes(json_data: dict, boundary: bytes) -> bytes:
    json_str = json.dumps(json_data, separators=(",", ":"))  # pas d'espaces superflus
    part = (
        b"--" + boundary + b"\r\n"
        b"Content-Type: application/json\r\n\r\n"
        + json_str.encode("utf-8") + b"\r\n"
    )
    return part

def establish_pdu(pduSessionId, token, supi="imsi-208930000000001", pei="imeisv-4370816125816151", sst=1, sd="010203", mcc="208", mnc="93", display=True):

    boundary = uuid.uuid4().hex.encode()  # boundary doit être en bytes
    json_data = {
        "supi": supi,
        "pei": pei,
        "gpsi": "msisdn-1",
        "pduSessionId": pduSessionId,
        "dnn": "internet",
        "sNssai": {
            "sst": sst,
            "sd": sd
        },
        "servingNfId": "b94d7d29-e99f-4c13-afb6-daf1b2f72a11",
        "guami": {
            "plmnId": {
                "mcc": mcc,
                "mnc": mnc
            },
            "amfId": "cafe00"
        },
        "servingNetwork": {
            "mcc": mcc,
            "mnc": mnc
        },
        "n1SmMsg": {
            "contentId": "n1SmMsg"
        },
        "anType": "3GPP_ACCESS",
        "ratType": "NR",
        "ueLocation": {
            "nrLocation": {
                "tai": {
                    "plmnId": {
                        "mcc": mcc,
                        "mnc": mnc
                    },
                    "tac": "000001"
                },
                "ncgi": {
                    "plmnId": {
                        "mcc": mcc,
                        "mnc": mnc
                    },
                    "nrCellId": "000000010"
                },
                "ageOfLocationInformation": -342971918,
                "ueLocationTimestamp": "2025-03-26T16:29:39.025515006Z"
            }
        },
        "ueTimeZone": "+00:00",
        "smContextStatusUri": "http://amf.free5gc.org:8000/namf-callback/v1/smContextStatus/imsi-208930000000001/1"
    }

    json_part = json_to_multipart_bytes(json_data, boundary)

    pkt = NAS5GSM(msg_type=0xc1)/NASMaxDataRate()/NASPDUSessionType(eid=0x9, type=0x1)
    pkt = pkt/NASSSCMode()/NAS5GSMCapability()/NASExtPCO()

    nas_part = (
        b"--" + boundary + b"\r\n"
        b"Content-Id: n1SmMsg\r\n"
        b"Content-Type: application/vnd.3gpp.5gnas\r\n\r\n"
        + raw(pkt)
    )

    end = b"--" + boundary + b"--\r\n"
    body = json_part + nas_part + end

    uri = f"/nnrf-disc/v1/nf-instances"

    return request_cn("SMF", body, "POST", uri, token=token, display=display)
