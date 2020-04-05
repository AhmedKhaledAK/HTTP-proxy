# Parallel HTTP Proxy with Caching

Implementing a parallel HTTP proxy with caching, you can even use it as your browser's proxy!

If you're not familiar with HTTP, read about it [here](https://tools.ietf.org/html/rfc1945). 

If you're not familiar with what a proxy is, read about it [here](https://www.varonis.com/blog/what-is-a-proxy-server/).

### Testing the proxy

---

Head over to the project's directory first.

To run the server, just type the following in a terminal:

```
python3 http_proxy.py
```

The default port number is 18888. So when testing with a client, make to sure to connect to 127.0.0.1:18888.

Connect to the server using ***telnet*** by typing the following in ***another*** terminal:

```
telnet 127.0.0.1 18888
```

After hitting enter, a TCP connection will be established between the client and the server. You can capture packets and filter them using ***Wireshark*** for example. 

After that, you can type in your request and send it to the server. Do so by typing, for example, this: 

````
GET www.apache.org/ HTTP/1.0
````

then hit enter twice. Once you do that you will find that the proxy sent back the response to you. The proxy also caches the response, so if you requested again with the same request it will respond to you much faster. 

### Testing multiple clients

---

To test multiple clients, you can use the script *test_parallel.py*. While the server is up and running, on a terminal, type the following:

```
python3 test_cases.py 
```

It will run multiple clients and the server will respond to them. Not necessarily to be sequential responses at all. 



