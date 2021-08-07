#/bin/python

#https://support.f5.com/csp/article/K6917 (Reference: Overview of BIG-IP persistence cookie encoding)

import re, requests, struct, sys

url = raw_input("URL: ")

req = requests.head('https://' + url)
try:
        if req.status_code == 200:
                pool = req.headers['Set-Cookie']
                print("")
                if pool.__contains__("BIGipServer"):
                        pool_name = re.search('BIGipServer(.+?)=', pool)
                        p = pool_name.group(1)
                        print("POOL NAME: " + p)
                        print("")

                        pool_member = re.search('=(.+?);', pool)
                        pm = pool_member.group(1)

                        def decode(pm):
                                (host, port, end) = pm.split('.')
                                (a, b, c, d) = [ord(i) for i in struct.pack("<I", int(host))]
                                p = [ord(i) for i in struct.pack("<I", int(port))]
                                portOut = p[0]*256 + p[1]
                                print("POOL MEMBER = %s.%s.%s.%s:%s" % (a,b,c,d,portOut))
                        decode(pm)
                else:
                        print("SET-COOKIE ENCRYPTED OR FRONT NOT VULN WITH BIG-IP")

        elif req.status_code == 301:
                print(req.status_code)
                redirect = req.headers['location']
                print("REDIRECT URL TO: " + redirect)

        else:
                print("HTTP CODE RESPONSE --> ", req.status_code)


except KeyError:
        print("THERE IS NO 'SET-COOKIE' PARAMETER ON REQUEST RESPONSE")
