from .cookies import cookiejar_from_dict
from .structures import CaseInsensitiveDict

from http.cookiejar import CookieJar
from typing import Union
import json


class Response:
    """object, which contains the response to an HTTP request."""

    def __init__(self):
        # Integer Code of responded HTTP Status, e.g. 404 or 200.
        self.status_code = None

        # String of responded HTTP Body.
        self.text = None

        # Case-insensitive Dictionary of Response Headers.
        self.headers = CaseInsensitiveDict()

        # A CookieJar of Cookies the server sent back.
        self.cookies = cookiejar_from_dict({})

    def __enter__(self):
        return self

    def __repr__(self):
        return f"<Response [{self.status_code}]>"

    def json(self, **kwargs):
        """parse response body to json (dict/list)"""
        return json.loads(self.text, **kwargs)


def build_response(res: Union[dict, list], res_cookies: CookieJar) -> Response:
    """Builds a Response object """
    response = Response()

    # Fallback to None if there's no status_code, for whatever reason.
    response.status_code = res["status"]

    # Make headers case-insensitive.
    response_headers = {}
    if res["headers"] is not None:
        for header_key, header_value in res["headers"].items():
            if len(header_value) == 1:
                response_headers[header_key] = header_value[0]
            else:
                response_headers[header_key] = header_value
    response.headers = response_headers

    # Add new cookies from the server.
    response.cookies = res_cookies
    return response
