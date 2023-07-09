import tls_client

session = tls_client.Session(
    client_identifier="chrome_113",
    random_tls_extension_order=True,
)

session.get('https://httpbin.org/cookies/set/testcookie/12345')
session.get('https://httpbin.org/cookies/set/abc/67890')

print(session.cookies.get_dict())
print(session.get('https://httpbin.org/cookies').text)
session.cookies.set("abc", value=None, domain="httpbin.org", path="/")
print(session.cookies.get_dict())
print(session.get('https://httpbin.org/cookies').json())
print(session.cookies.get_dict())
print(session.get('https://httpbin.org/cookies').json())

session.close()