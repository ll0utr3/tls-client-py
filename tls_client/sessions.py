from .cffi import request, freeMemory, destroySession
from .cookies import cookiejar_from_dict, merge_cookies, extract_cookies_to_jar
from .exceptions import TLSClientExeption
from .response import build_response
from .structures import CaseInsensitiveDict

from typing import Any, Optional, Union
from ujson import dumps, loads
import urllib.parse
import base64
import ctypes
import uuid


class Session:

    def __init__(
            self,
            client_identifier: Optional[str] = None,
            ja3_string: Optional[str] = None,
            h2_settings: Optional[dict] = None,  # Optional[dict[str, int]]
            h2_settings_order: Optional[list] = None,  # Optional[list[str]]
            supported_signature_algorithms: Optional[list] = None,  # Optional[list[str]]
            supported_delegated_credentials_algorithms: Optional[list] = None,  # Optional[list[str]]
            supported_versions: Optional[list] = None,  # Optional[list[str]]
            key_share_curves: Optional[list] = None,  # Optional[list[str]]
            cert_compression_algo: str = None,
            additional_decode: str = None,
            pseudo_header_order: Optional[list] = None,  # Optional[list[str]
            connection_flow: Optional[int] = None,
            priority_frames: Optional[list] = None,
            header_order: Optional[list] = None,  # Optional[list[str]]
            header_priority: Optional[dict] = None,  # Optional[list[str]]
            random_tls_extension_order: Optional = False,
            force_http1: Optional = False,
            catch_panics: Optional = False,
            debug: Optional = False,

            disable_cookies: bool = True,
            disable_keepalive: bool = True,
            verify: bool = True,
    ) -> None:
        self._session_id = str(uuid.uuid4())

        self.proxy: str = ""

        self.verify = verify

        self.params = {}

        self.cookies = cookiejar_from_dict({})
        self.cookies.session_id = self._session_id
        self.timeout = 30

        self.client_identifier = client_identifier
        self.ja3_string = ja3_string
        self.h2_settings = h2_settings
        self.h2_settings_order = h2_settings_order
        self.supported_signature_algorithms = supported_signature_algorithms
        self.supported_delegated_credentials_algorithms = supported_delegated_credentials_algorithms
        self.supported_versions = supported_versions
        self.key_share_curves = key_share_curves
        self.cert_compression_algo = cert_compression_algo
        self.additional_decode = additional_decode
        self.pseudo_header_order = pseudo_header_order
        self.connection_flow = connection_flow
        self.priority_frames = priority_frames
        self.header_order = header_order
        self.header_priority = header_priority
        self.random_tls_extension_order = random_tls_extension_order
        self.force_http1 = force_http1
        self.catch_panics = catch_panics
        self.debug = debug

        self.disable_cookies: bool = disable_cookies
        self.disable_keepalive: bool = disable_keepalive

    def execute_request(
            self,
            method: str,
            url: str,
            params: Optional[dict] = None,

            data: Optional[Union[str, dict]] = None,
            json: Optional[dict] = None,
            content: str | bytes | None = None,

            headers: Optional[dict] = None,
            cookies: Optional[dict] = None,
            allow_redirects: Optional[bool] = False,
            verify: bool = True,
            timeout: int | None = None,
            proxy: str | None = None,

            custom_host: str = "",
    ):
        verify = self.verify or verify
        # --- URL ------------------------------------------------------------------------------------------------------
        # Prepare URL - add params to url
        if params is not None:
            url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"

        # --- Request Body ---------------------------------------------------------------------------------------------
        # Prepare request body - build request body
        # Data has priority. JSON is only used if data is None.
        if json is not None:
            request_body = dumps(json)
            content_type = "application/json"
        elif data is not None:
            request_body = urllib.parse.urlencode(data, doseq=True)
            content_type = "application/x-www-form-urlencoded"
        else:
            request_body = content
            content_type = None

        if headers is None:
            headers = {}
        headers = CaseInsensitiveDict(headers)
        if content_type is not None and "Content-Type" not in headers:
            if content_type is not None:
                headers["Content-Type"] = content_type
        if "Accept-Encoding" not in headers:
            headers["Accept-Encoding"] = "gzip, deflate, br"

        # --- Cookies --------------------------------------------------------------------------------------------------
        cookies = cookies or {}
        # Merge with session cookies
        cookies = merge_cookies(self.cookies, cookies)
        # turn cookie jar into dict
        # in the cookie value the " gets removed, because the fhttp library in golang doesn't accept the character
        request_cookies = [
            {'domain': c.domain, 'expires': 99999, 'name': c.name, 'path': c.path,
             'value': c.value.replace('"', "")}
            for c in cookies
        ]
        # --- Proxy ----------------------------------------------------------------------------------------------------
        proxy = proxy or self.proxy

        # --- Timeout --------------------------------------------------------------------------------------------------
        # maximum time to wait

        timeout_seconds = timeout or self.timeout
        # --- Request --------------------------------------------------------------------------------------------------
        is_byte_request = isinstance(request_body, (bytes, bytearray))
        request_payload = {
            "serverNameOverwrite": custom_host,
            "sessionId": self._session_id,
            "followRedirects": allow_redirects,
            "forceHttp1": self.force_http1,
            "withDebug": self.debug,
            "catchPanics": self.catch_panics,
            "headers": dict(headers),
            "headerOrder": self.header_order,
            "insecureSkipVerify": not verify,
            "isByteRequest": is_byte_request,
            "additionalDecode": self.additional_decode,
            "proxyUrl": proxy,
            "requestUrl": url,
            "requestMethod": method,
            "requestBody": base64.b64encode(request_body).decode() if is_byte_request else request_body,
            "requestCookies": request_cookies,
            "timeoutSeconds": timeout_seconds,
            "withoutCookieJar": self.disable_cookies,
            "transportOptions": {
                "disableKeepAlives": self.disable_keepalive,
                # "disableCompression": False,
                "maxIdleConns": 60 if not self.disable_keepalive else 0,
                "maxIdleConnsPerHost": 50 if not self.disable_keepalive else 0,
                # "maxConnsPerHost": 65535,
                # "maxResponseHeaderBytes": 0,
                # "writeBufferSize": 0,
                # "readBufferSize": 0,
                "idleConnTimeout": 60000000000 if not self.disable_keepalive else 0,
            }
        }
        if self.client_identifier is None:
            request_payload["customTlsClient"] = {
                "ja3String": self.ja3_string,
                "h2Settings": self.h2_settings,
                "h2SettingsOrder": self.h2_settings_order,
                "pseudoHeaderOrder": self.pseudo_header_order,
                "connectionFlow": self.connection_flow,
                "priorityFrames": self.priority_frames,
                "headerPriority": self.header_priority,
                "certCompressionAlgo": self.cert_compression_algo,
                "supportedVersions": self.supported_versions,
                "supportedSignatureAlgorithms": self.supported_signature_algorithms,
                "supportedDelegatedCredentialsAlgorithms": self.supported_delegated_credentials_algorithms,
                "keyShareCurves": self.key_share_curves,
            }
        else:
            request_payload["tlsClientIdentifier"] = self.client_identifier
            request_payload["withRandomTLSExtensionOrder"] = self.random_tls_extension_order

        # this is a pointer to the response
        response = request(dumps(request_payload).encode('utf-8'))
        # dereference the pointer to a byte array
        response_bytes = ctypes.string_at(response)
        # convert our byte array to a string (tls client returns json)
        response_string = response_bytes.decode('utf-8')
        # convert response string to json
        response_object = loads(response_string)
        # free the memory
        freeMemory(response_object['id'].encode('utf-8'))
        # --- Response -------------------------------------------------------------------------------------------------
        # Error handling
        if response_object["status"] == 0:
            raise TLSClientExeption(response_object["body"])
        # Set response cookies
        response_cookie_jar = extract_cookies_to_jar(
            request_url=url,
            request_headers=headers,
            cookie_jar=cookies,
            response_headers=response_object["headers"]
        )
        # build response class
        return build_response(response_object, response_cookie_jar)

    def get(
            self,
            url: str,
            **kwargs: Any
    ):
        """Sends a GET request"""
        return self.execute_request(method="GET", url=url, **kwargs)

    def options(
            self,
            url: str,
            **kwargs: Any
    ):
        """Sends a OPTIONS request"""
        return self.execute_request(method="OPTIONS", url=url, **kwargs)

    def head(
            self,
            url: str,
            **kwargs: Any
    ):
        """Sends a HEAD request"""
        return self.execute_request(method="HEAD", url=url, **kwargs)

    def post(
            self,
            url: str,
            data: Optional[Union[str, dict]] = None,
            json: Optional[dict] = None,
            **kwargs: Any
    ):
        """Sends a POST request"""
        return self.execute_request(method="POST", url=url, data=data, json=json, **kwargs)

    def put(
            self,
            url: str,
            data: Optional[Union[str, dict]] = None,
            json: Optional[dict] = None,
            **kwargs: Any
    ):
        """Sends a PUT request"""
        return self.execute_request(method="PUT", url=url, data=data, json=json, **kwargs)

    def patch(
            self,
            url: str,
            data: Optional[Union[str, dict]] = None,
            json: Optional[dict] = None,
            **kwargs: Any
    ):
        """Sends a PATCH request"""
        return self.execute_request(method="PATCH", url=url, data=data, json=json, **kwargs)

    def delete(
            self,
            url: str,
            **kwargs: Any
    ):
        """Sends a DELETE request"""
        return self.execute_request(method="DELETE", url=url, **kwargs)

    def close(self):
        r = destroySession(dumps({"sessionId": self._session_id}).encode())
        response = loads(ctypes.string_at(r).decode('utf-8'))
        freeMemory(response['id'].encode('utf-8'))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
