import logging

from pathlib import Path
from mitmproxy import ctx, http


class ContentReplace:
    def content(self, flow: http.HTTPFlow) -> None:
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
        content_path = Path("CONTENT", content_dir, content_file)
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
        
        if not content_path.is_file():
            logging.error(f"... and no dump here to serve")
            return
        
        
        logging.error(f"... and trying to serve dump")
        flow.response.status_code = 200
        headers = flow.response.headers
        
        headers["Content-Length"] = str(content_path.stat().st_size)
        headers["Content-Type"] = "binary/octet-stream"
        
        with open(content_path, "rb") as binary_file:
            flow.response.content = binary_file.read()          
        
    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response or not flow.response.content:
            return
        
        if flow.request.path.startswith("/v1/content/") or flow.request.path.startswith("/v2/content/"):
            self.content(flow)
            
    def request(self, flow: http.HTTPFlow) -> None:
        pass
        
addons = [ContentReplace()]