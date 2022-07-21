import sys
import socket
import concurrent.futures
import itertools

from censys.search import CensysHosts
h = CensysHosts()


def check_socks_proxy(socks_version, ip_port):
    payload = bytes([])
    if (socks_version == 5):
        payload = bytes([ 0x05, 0x01, 0x00 ])
    else:
        google_ip = socket.inet_aton(socket.gethostbyname("www.google.com"))
        payload = bytes([ 0x04, 0x01, 0x00, 0x50 ])
        payload += google_ip
        payload += bytes("socksniffer\0", 'ascii')
        
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    response = bytes([])

    try:
        s.settimeout(5)
        s.connect(ip_port)
        s.sendall(payload)
        response = s.recv(16)
    except:
        return None
        
        s.close()

    if (len(response) < 2):
        return None

    if (socks_version == 5):
        if (response[0] == 0x05) and (response[1] == 0x00):
            return ip_port
        else:
            return None
    else:
        if (response[0] == 0x00) and (response[1] == 0x5a):
            return ip_port
        else:
            return None


def get_ip_port_list(socks_version, page):
    #This approach will consume your queries way too quickly
    #better to just check all unknown services
    '''
    hosts_data = page.view_all()

    ip_port_list = []

    for host in hosts_data.items():
        ip = host[0]
        port_list = []
        
        for service in host[1]["services"]:
            try:
                if (socks_version == 5):
                    if (service["banner_hex"] == "0500") or (service["banner_hex"] == "05ff"):
                        port_list.append(service["port"])
                else:
                    if (service["banner_hex"].startswith("005b") and len(service["banner_hex"]) == 16):
                        port_list.append(service["port"])
            except:
                continue
        
        for port in port_list:
            ip_port_list.append((ip, port))

    return ip_port_list
    '''
    
    ip_port_list = []
    page_data = page()
    
    for host in page_data:
        ip = host["ip"]
        port_list = []

        for service in host["services"]:
            try:
                if (service["service_name"] == "UNKNOWN"):
                    port_list.append(service["port"])
            except:
                continue

        for port in port_list:
            ip_port_list.append((ip, port))

    return ip_port_list


def create_query(socks_version, port_list, country_list, country_exclusion):
    socks_query = ""
    port_query = ""
    country_query = ""
    full_query  = ""
    
    if (socks_version == 5):
        socks_query = "(services.banner_hex:0500 or services.banner_hex:05ff)"
    else:
        socks_query = "services.banner_hex:005b????????????"

    full_query = "same_service(" + socks_query;

    if (len(port_list) > 0):
        port_query = "services.port:{0}".format(port_list[0])
        if (len(port_list) > 1):
            for port in port_list[1:]:
                port_query += " or services.port:{0}".format(port)
        full_query += " and (" + port_query + ")"
    
    full_query += ")"

    if (len(country_list) > 0):
        country_query = "location.country_code:{0}".format(country_list[0])
        if (len(country_list) > 1):
            for country in country_list[1:]:
                country_query += " or location.country_code:{0}".format(country)
        full_query += " and (" + country_query + ")"
    
    elif (len(country_exclusion) > 0):
        country_query = "not location.country_code:{0}".format(country_exclusion[0])
        if (len(country_exclusion) > 1):
            for country in country_exclusion[1:]:
                country_query += " and not location.country_code:{0}".format(country)
        full_query += " and (" + country_query + ")"
    
    return full_query


def print_help():
    print("Usage: socksniffer.py [-s SOCKS_version] [-f output_file] [-m max_proxy_count] [-p port_list] [-cL country_list] [-cX country_exclusions]")
    print("    -s: SOCKS proxy version, can be 4 or 5")
    print("    -p:  Comma seperated list of accepted SOCKS ports")
    print("    -cL: Comma seperated list of accepted country codes in which the proxies reside, example: -cL FR,US,DE")
    print("    -cX: Comma seperated list of rejected country codes, example: -cX CN,RU")



def main():
    if (len(sys.argv) <= 2):
        print_help()
        return 0

    socks_version = 0
    output_file = ""
    max_proxy_count = 0
    str_port_list = []
    port_list = []
    country_list = []
    country_exclusions = []

    for i in range(1, len(sys.argv)):
        if sys.argv[i] == '-s':
            socks_version = int(sys.argv[i+1])
        elif sys.argv[i] == '-f':
            output_file = sys.argv[i+1]
        elif sys.argv[i] == '-m':
            max_proxy_count = int(sys.argv[i+1])
        elif sys.argv[i] == '-p':
            str_port_list = sys.argv[i+1].split(',')
            for port in str_port_list:
                port_list.append(int(port))
        elif sys.argv[i] == '-cL':
            country_list = sys.argv[i+1].split(',')
        elif sys.argv[i] == '-cX':
            country_exclusions = sys.argv[i+1].split(',')

    if (socks_version != 4) and (socks_version != 5):
        print("SOCKS Version invalid or unspecified (can only be 4 or 5")
        return 0

    if (len(output_file) == 0):
        print("No output file specified")
        return 0

    print("Starting search for SOCKS{0} proxies:".format(socks_version))

    query = create_query(socks_version, port_list, country_list, country_exclusions)
    
    out_file_obj = open(output_file, 'a')

    potential_proxy_count = 0
    invalid_proxy_count = 0
    valid_proxy_count = 0
    page = h.search(query, per_page=100)
    while(page.pages > 0):
        if (valid_proxy_count >= max_proxy_count) and (max_proxy_count > 0):
            break

        ip_port_list = get_ip_port_list(socks_version, page)
        potential_proxy_count += len(ip_port_list)
        if (len(ip_port_list) == 0):
            break
            
        executor = concurrent.futures.ThreadPoolExecutor()
        executor_results = executor.map(check_socks_proxy, itertools.repeat(socks_version), ip_port_list)
        proxy_check_results = list(executor_results)

        for proxy in proxy_check_results:
            if (valid_proxy_count >= max_proxy_count) and (max_proxy_count > 0):
                break

            if (proxy == None):
                invalid_proxy_count += 1
            else:
                valid_proxy_count += 1
                out_file_obj.write("{0}:{1}\n".format(proxy[0], proxy[1]))

        print("{0} valid proxies, {1} invalid proxies out of {2} potential proxies. ({3:.2f}% valid)".format(valid_proxy_count, invalid_proxy_count, potential_proxy_count, (valid_proxy_count/potential_proxy_count) * 100), end="\r")
        
        page = h.search(query, cursor=page.nextCursor, per_page=100)

    print("\nfound {} valid proxies in total".format(valid_proxy_count))
    

if __name__ == "__main__":
    main()
