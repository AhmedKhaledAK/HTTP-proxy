
# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import re


class HttpRequestInfo(object):
    """
    Represents a HTTP request information
    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.
    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.
    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.
    requested_host: the requested website, the remote website
    we want to visit.
    requested_port: port of the webserver we want to visit.
    requested_path: path of the requested resource, without
    including the website name.
    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # Headers will be represented as a list of tuples
        # for example ("Host", "www.google.com")
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ("Host", "www.google.com") note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:
        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n
        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """

        print("*" * 50)
        print("[to_http_string] Implement me!")
        print("*" * 50)
        return None

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        """ Same as above """
        pass

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.
    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.
    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """

    setup_sockets(proxy_port_number)
    return None


def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.
    But feel free to add your own classes/functions.
    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)

    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    serveraddr = ("127.0.0.1", proxy_port_number)

    serversock.bind(serveraddr)
    serversock.listen(12)
    clientsock, clientaddr = serversock.accept()
    print(f"received from {clientaddr}")

    buffer = []
    httpstr = ""

    while True:
        httppacket = clientsock.recv(4096)
        print(f"http packet: {httppacket}")
        buffer += httppacket
        httpstr += httppacket.decode("ascii")
        print(f"bytearray: {buffer}")
        print(f"str: {httpstr}")
        if buffer[-4:] == [13, 10, 13, 10]:
            print("done receiving")
            break
    
    print("buffer: ", buffer)
    print("httsptr: ", httpstr)
    http_request_pipeline(clientaddr, httpstr)

    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.
    return None


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
    pass


def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.
    - Parses the given HTTP request
    - Validates it
    - Returns a sanitized HttpRequestInfo or HttpErrorResponse
        based on request validity.
    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.
    Please don't remove this function, but feel
    free to change its content
    """
    # Parse HTTP request
    parsed = parse_http_request(source_addr, http_raw_data)
    print("obj client info:", parsed.client_address_info)
    print("obj method:", parsed.method)
    print("obj req host:", parsed.requested_host)
    print("obj req path:", parsed.requested_path)
    print("obj req port:", parsed.requested_port)
    print("obj req headers:", parsed.headers)

    state = check_http_request_validity(http_raw_data)
    if state == HttpRequestState.GOOD:
        sanitize_http_request(parsed)
    
    # Validate, sanitize, return Http object.
    return None


def get_port(searchstr):
    if searchstr == None:
        return 80, -1
    match = re.search(":\d+",searchstr)
    print("match port:",match)
    if match != None:
        print("group port:",match.group()[1:])
        port = int(match.group()[1:])
        return port, searchstr.find(match.group())
    return 80, -1

def parse_http_request(source_addr, http_raw_data) -> HttpRequestInfo:
    """
    This function parses an HTTP request into an HttpRequestInfo
    object.
    it does NOT validate the HTTP request.
    """

    method = None
    host = None
    path = None
    version = None
    port = 80
    headerslist = []

    requestln = http_raw_data[:http_raw_data.index('\n')] 

    match = re.search(r"([a-zA-Z-._~:/?#[\]@!$&'()*+,;=%0-9]+)\s+([a-zA-Z-._~:/?#[\]@!$&'()*+,;=%0-9]+)\s+([a-zA-Z-._~:/?#[\]@!$&'()*+,;=%0-9]+)", requestln)
    if match != None:
        print("group0:",match.group(0))
        print("group1:",match.group(1))
        print("group2:",match.group(2))
        print("group3:",match.group(3))
        method = match.group(1).lower().strip()
        path = match.group(2).lower().strip()
        port, port_idx = get_port(path)
        if port_idx != -1:
            port_digits = len(str(port))+1
            path = path[:port_idx] + path[port_idx+port_digits:]
        print("new path: ", path)
        print("port = ", port)
        version = match.group(3).lower().strip()
        
    headers = http_raw_data[http_raw_data.index('\n')+1:]
    
    tupleslist = re.findall(r"([a-zA-Z0-9 -]+):[^\n\ra-zA-Z/:.0-9();,+=*\" -]*([a-zA-Z/:.0-9();,+=*\" -]+)", headers)

    for h in tupleslist:
        h = list(h)
        headerslist.append(h)
        h[0] = h[0].lower().strip()
        h[1] = h[1].lower().strip()
        if h[0] == "host":
            host = h[1]
            if port == 80:
                port, idx = get_port(h[1])
                if idx != -1:
                    h[1] = h[1][0:idx]

    print("headerslist", headerslist)
        
    # Replace this line with the correct values.
    ret = HttpRequestInfo(source_addr, method, host, port, path, headerslist)
    return ret


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    """
    Checks if an HTTP response is valid
    returns:
    One of values in HttpRequestState
    """

    http_request_info = parse_http_request(None, http_raw_data)

    method = http_request_info.method
    path = http_request_info.requested_path
    host = http_request_info.requested_host
    port = http_request_info.requested_port
    headers = http_request_info.headers

    if method == None or path == None:
        print("invalid input")
        return HttpRequestState.INVALID_INPUT

    if method == "head" or method == "post" or method == "put":
        print("not supported")
        return HttpRequestState.NOT_SUPPORTED

    print("valid method:",method)

    if port > 65536:
        print("port is big!")
        return HttpRequestState.INVALID_INPUT

    print("valid port:", port)
    
    # return HttpRequestState.GOOD (for example)
    return HttpRequestState.GOOD



def sanitize_http_request(request_info: HttpRequestInfo):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.
    for example, expand a full URL to relative path + Host header.
    returns:
    nothing, but modifies the input object
    """

    host = request_info.requested_host
    path = request_info.requested_path
    port = request_info.requested_port
    method = request_info.method
    headerslist = request_info.headers
    clientaddr = request_info.client_address_info

    # format 2 already, nothing has to be done
    if host != None:
        print("format 2 already")
        return

    # format 2, split hostname from path variable
    match = re.search(r"([(http(s)?):\/\/(www\.)?a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6})\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)", path)

    if match != None:
        print("complete match is ", match.group(0))
        print("complete match is ", match.group(1))
        print("complete match is ", match.group(2))
        request_info.requested_host = match.group(1)
        request_info.requested_path = match.group(2)

#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*
    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")


def main():
    """
    Please leave the code in this function as is.
    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
