#!/usr/bin/python

import BaseHTTPServer

try:
    import httplib2
except:
    try:
        import sys
	sys.path.append("httplib2/python2/")
        import httplib2
    except:
        raise

try:
    import oauth2
except:
    try:
        import sys
        sys.path.append("python-oauth2")
        import oauth2
    except:
        raise

import base64
import ConfigParser

class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    client = None
    user = None

    def check_auth(s):
        if 'authorization' not in s.headers:
            s.send_response(401)
            s.send_header("WWW-Authenticate", 'Basic realm="Secure Area"')
            s.end_headers()
            return False

        if s.headers['authorization'].split()[1] != Handler.user:
            s.send_response(403)
            s.end_headers()
            return False

        return True

    def do_POST(s):
        if Handler.check_auth(s) == False:
            return

        l = int(s.headers['content-length'])
        data = s.rfile.read(l)

        # construct the twitter url
        url = "http://api.twitter.com%s" % s.path

        (resp, body) = Handler.client.request(url, "POST", data)
        s.send_response(int(resp['status']))

#        print resp, body
        [s.send_header(key, value) for (key, value) in resp.items() if key != 'status']

        s.end_headers()
        s.wfile.write(body)
        s.wfile.close()

    def do_GET(s):
        #        print s.headers
        if Handler.check_auth(s) == False:
            return

        # construct the twitter url
        url = "http://api.twitter.com%s" % s.path
#        print url

        (resp, body) = Handler.client.request(url)
#        print body, resp
        s.send_response(int(resp['status']))

        [s.send_header(key, value) for (key, value) in resp.items() if key != 'status']

        s.end_headers()
        s.wfile.write(body)
        s.wfile.close()


if __name__ == '__main__':
    conf = ConfigParser.ConfigParser()
    conf.read("twitter.ini")

    Handler.client = oauth2.Client(oauth2.Consumer(conf.get("twitter", "CONSUMER_KEY"),
                                                   conf.get("twitter", "CONSUMER_SECRET")),
                                   oauth2.Token(conf.get("twitter", "TOKEN"),
                                                conf.get("twitter", "TOKEN_SECRET")))

    Handler.client.set_signature_method(oauth2.SignatureMethod_HMAC_SHA1())

    user = "%s:%s" % (conf.get("twitter", "USER"), conf.get("twitter", "PASS"))
    Handler.user = user.encode('base64')[:-1]

    addr = (conf.get("twitter", "HOST_NAME"), conf.getint("twitter", "PORT_NUMBER"))
    httpd = BaseHTTPServer.HTTPServer(addr, Handler)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
