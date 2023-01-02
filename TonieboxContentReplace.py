import logging
import base64
import copy
import os

from pathlib import Path
from mitmproxy import ctx, http

import sys
from toniebox.pb.freshness_check.fc_request_pb2 import TonieFreshnessCheckRequest, TonieFCInfo
from toniebox.pb.freshness_check.fc_response_pb2 import TonieFreshnessCheckResponse

class TonieboxContentReplace:
    def __init__(self):
        logging.warn(f"Start: TonieboxContentReplace")
        self.module_dir = Path(__file__).parent

        env_cont_dir = os.environ.get("TONIEBOX_CONTENT_DIR")
        if env_cont_dir is None:
            self.content_dir = Path(self.module_dir, "CONTENT")
        else:
            self.content_dir = Path(env_cont_dir)

        sys.path.append(self.module_dir)
        
        logging.warn(f"module_path={self.module_dir}, content_dir={self.content_dir}")
        
    def add_headers(self, headers):
        headers["Server"] = "openresty"
        headers["Connection"] = "keep-alive"
        del headers["Content-Length"]
        
    def handle_content(self, flow: http.HTTPFlow, content_path) -> None:   
        flow.backup() #mark content as modified  
        if not content_path.is_file():
            logging.warn(f"... and no dump here to serve")
            
            response = http.Response.make(
                410,  # HTTP status code
                b"GONE"  # HTTP status message
            )
            self.add_headers(response.headers)
            goneBytes = bytes('{"error":{"title":"Gone","status":410}}', 'UTF-8')
            response.headers["Content-Length"] = str(goneBytes)
            response.headers["Content-Type"] = "application/json; charset=utf-8"
            response.content = goneBytes
            flow.response = response
            return
        
        logging.warn(f"... and trying to serve dump")
        
        # Set the response for the flow
        response = http.Response.make(
            200,  # HTTP status code
            b"OK",  # HTTP status message
        )
        self.add_headers(response.headers)
                
        response.headers["Content-Length"] = str(content_path.stat().st_size)
        response.headers["Content-Type"] = "binary/octet-stream"
        
        with open(content_path, "rb") as binary_file:
            response.content = binary_file.read()   
        
        flow.response = response
        
    def request_content(self, flow: http.HTTPFlow) -> None:
        api_version = "v1"
        if flow.request.path.startswith("/v2/"):
            api_version = "v2"
            
        content_id = flow.request.path[12:]
        
        logging.warn(f"Api={api_version}, content_id={content_id}")
        if (len(content_id) != 16):
            logging.error(f"len(content_id)={len(content_id)}!=16")
            return
        
        content_dir = content_id[:8].upper()
        content_file = content_id[8:].upper()
        content_path = Path(self.content_dir, content_dir, content_file)
        content_nocloud_path = Path(self.content_dir, content_dir, content_file + ".nocloud")
        
        if not content_nocloud_path.is_file():
            if not self.is_valid_tonie_auth_header(flow.request.headers):
                logging.warn(f"invalid authorization header, creating nocloud file")
                Path(content_nocloud_path).parent.mkdir(parents=True, exist_ok=True)
                open(content_nocloud_path, 'a').close()
            else:
                return
        
        logging.warn(f"skipping cloud download")
        self.handle_content(flow, content_path)
        
    def response_content(self, flow: http.HTTPFlow) -> None:
        if flow.modified(): #request got modified by us
            return
        
        api_version = "v1"
        if flow.request.path.startswith("/v2/"):
            api_version = "v2"
            
        content_id = flow.request.path[12:]
        
        logging.warn(f"Api={api_version}, content_id={content_id}")
        if (len(content_id) != 16):
            logging.error(f"len(content_id)={len(content_id)}!=16")
            return
        
        content_dir = content_id[:8].upper()
        content_file = content_id[8:].upper()
        content_path = Path(self.content_dir, content_dir, content_file)
        content_nocloud_path = Path(self.content_dir, content_dir, content_file + ".nocloud")
        logging.warn(f"FullPath={content_path.resolve()}, content_dir={content_dir}, content_file={content_file}")
        
        if flow.response.status_code == 200: #or flow.response.status_code == 206: partial content!
            logging.warn(f"Status code {flow.response.status_code} - content known...")
            if content_path.is_file():
                logging.warn(f"... and already dumped")
            else:
                logging.warn(f"... and dumping")
                Path(content_path).parent.mkdir(parents=True, exist_ok=True)
                with open(content_path, "wb") as binary_file:
                    binary_file.write(flow.response.content)                
            return
            
        if not flow.response.status_code == 410:
            logging.error(f"Status code {flow.response.status_code} - to be implemented...")
            return
        
        logging.warn(f"Status code 410 - content unknown...")
        #TODO: Refine, only create file if its a custom tag (Auth header).
        
        # TODO: make configuratable
        #if not content_nocloud_path.is_file():
        #    logging.warn(f"... creating nocloud file")
        #    Path(content_nocloud_path).parent.mkdir(parents=True, exist_ok=True)
        #    open(content_nocloud_path, 'a').close()
            
        #self.handle_content(flow, content_path)  
    
    def uid2bytes(self, uid:int)-> bytes: 
        return uid.to_bytes(8, 'big')
    def uid2text(self, uid:int)-> str: 
        return uid.to_bytes(8, 'big').hex(":").upper()
    def uid2path(self, uid:int)-> list: 
        uid_bytes = uid.to_bytes(8, 'little')
        result = [
            uid_bytes[0:4].hex().upper(),
            uid_bytes[4:].hex().upper()
        ]
        return result
    
    def is_valid_tonie_auth_header(self, headers) -> bool:
        if not 'Authorization' in headers:
            return False
        if headers["Authorization"] == "BD 0000000000000000000000000000000000000000000000000000000000000000":
            return False
        return True
    
    def request_freshness_check(self, flow: http.HTTPFlow) -> None:              
        tonieInfos = TonieFreshnessCheckRequest()
        tonieInfos_mod = TonieFreshnessCheckRequest()
        tonieInfos.ParseFromString(flow.request.content)
        for info in tonieInfos.tonie_infos:
            path_parts = self.uid2path(info.uid)
            content_nocloud_path = Path(self.content_dir, path_parts[0], path_parts[1] + ".nocloud")
            logging.warn(f"FC-Request: uid={self.uid2text(info.uid)}, audioId={info.audio_id}")
            if content_nocloud_path.is_file():
                logging.warn("Removed...")
            else:
                tonieInfos_mod.tonie_infos.append(info)
                
        tonieInfoBytes = tonieInfos_mod.SerializeToString()
        flow.request.headers["Content-Length"] = str(len(tonieInfoBytes))
        flow.request.content = tonieInfoBytes
          
    def response_freshness_check(self, flow: http.HTTPFlow) -> None:    
        #content_b64 = 'EAcYAyABKAEwATgDQAA=' #Contains no tonies to delete
        #b64_bytes = content_b64.encode('ascii')
        #content_bytes = base64.b64decode(b64_bytes)
        
        tonieFCResponse = TonieFreshnessCheckResponse()
        tonieFCResponse.ParseFromString(flow.response.content)
        tonieFCResponse_mod = copy.copy(tonieFCResponse)
        del tonieFCResponse_mod.tonie_marked[:]
        
        for uid in tonieFCResponse.tonie_marked:
            logging.warn(f"FC-Response: uid={self.uid2text(uid)}")
            path_parts = self.uid2path(uid)
            content_nocloud_path = Path(self.content_dir, path_parts[0], path_parts[1] + ".nocloud")
            if content_nocloud_path.is_file():
                logging.warn("Removed...")
            else:
                tonieFCResponse_mod.tonie_marked.append(uid)
        
        
        tonieFcResBytes = tonieFCResponse_mod.SerializeToString()
        flow.response.headers["Content-Length"] = str(len(tonieFcResBytes))
        flow.response.content = tonieFcResBytes

        # Access the decoded data

        #message = message_bytes.decode('ascii')
        #https://prod.de.tbs.toys/v1/freshness-check
        #Content: 
        #Content-Length: 14
    
    
    def request_claim(self, flow: http.HTTPFlow) -> None:
        content_id = flow.request.path[10:]
        
        logging.warn(f"content_id={content_id}")
        if (len(content_id) != 16):
            logging.error(f"len(content_id)={len(content_id)}!=16")
            return
        
        content_dir = content_id[:8].upper()
        content_file = content_id[8:].upper()
        content_path = Path(self.content_dir, content_dir, content_file)
        content_nocloud_path = Path(self.content_dir, content_dir, content_file + ".nocloud")
                
        if not content_nocloud_path.is_file():
            if not self.is_valid_tonie_auth_header(flow.request.headers):
                logging.warn(f"invalid authorization header, creating nocloud file")
                Path(content_nocloud_path).parent.mkdir(parents=True, exist_ok=True)
                open(content_nocloud_path, 'a').close()
            else:
                return
        
        logging.warn("Don't claim @ the cloud")
        
        # Set the response for the flow
        response = http.Response.make(
            200,  # HTTP status code
        )
        self.add_headers(response.headers)
                
        response.headers["Content-Length"] = "0"
        flow.response = response
            
    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.path.startswith("/v1/content/") or flow.request.path.startswith("/v2/content/"):
            self.request_content(flow)
        elif flow.request.path.startswith("/v1/claim/"):
            self.request_claim(flow)
        elif flow.request.path.startswith("/v1/freshness-check"):
            self.request_freshness_check(flow)
    
    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response or not flow.response.content:
            return
        
        if flow.request.path.startswith("/v1/content/") or flow.request.path.startswith("/v2/content/"):
            self.response_content(flow)
        elif flow.request.path.startswith("/v1/freshness-check"):
            self.response_freshness_check(flow)
        
#addons = [TonieboxContentReplace()]