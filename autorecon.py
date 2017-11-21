import os
import sys
import argparse
import dns.resolver
import pyasn
import signal
import netaddr
import logging
import multiprocessing
import time
from threading import Event
import queue


def domain_worker(resolver, recursive, subdomains, wild_cards, domain_queue, asn_queue,
                  network_queue, address_queue, domain_results, done):
    """
    Domain worker performs the following:
        domain to ip resolution
    Args:
        domain_queue:
        asn_queue:
        network_queue:
        address_queue:
        domain_results:
    """
    while not done.is_set():
        try:
            domain = domain_queue.get(timeout=1)
            logging.debug("Domain popped from the queue: {}".format(domain))

            if domain in domain_results:
                logging.debug("Domain already in results: {}".format(domain))
                continue

            domain_ip_addresses = resolve_domain(resolver, domain, wild_cards)

            if domain_ip_addresses is not None:
                for ip_addr in domain_ip_addresses:
                    if ip_addr in wild_cards:
                        continue
                    address_queue.put(ip_addr)
                if domain not in domain_results:
                    domain_queue.put(domain)
                    domain_results.append(domain)
                    if recursive:
                        for sub in subdomains:
                            fqdn = '.'.join([sub, domain])
                            domain_queue.put(fqdn)
                for ip_addr in domain_ip_addresses:
                    address_queue.put(ip_addr)

            domain_queue.task_done()
        except queue.Empty:
            time.sleep(1)
            continue
        except Exception as e:
            logging.error(e, exc_info=True)
            pass


def address_worker(asndb_file, domain_queue, asn_queue, network_queue,
                   address_queue, address_results, rdns_results, done):
    """
    Address worker performs the following tasks:
        xyz
    Args:
        asndb_file:
        domain_queue:
        asn_queue:
        network_queue:
        address_queue:
        address_results:
        rdns_results:
    """
    asndb_file = asndb_file

    while not done.is_set():
        try:
            ip_addr = address_queue.get(timeout=1)
            logging.debug("IP Address popped from the queue: {}".format(ip_addr))

            if ip_addr is not None and ip_addr not in address_results:
                address_results.append(ip_addr)
                rdns = get_rdns(ip_addr)

                if rdns is not None and rdns not in rdns_results:
                    rdns_results.append(rdns)

            ip_asn = (get_asn(ip_addr, asndb_file))

            if ip_asn is not None:
                asn_queue.put(ip_asn)
            address_queue.task_done()

        except queue.Empty:
            time.sleep(1)
            continue
        except Exception as e:
            logging.error(e, exc_info=True)
            pass


def asn_worker(asndb_file, domain_queue, asn_queue, network_queue, address_queue, asn_results, done):
    asndb_file = asndb_file

    while not done.is_set():
        try:
            asn = asn_queue.get(timeout=1)
            logging.debug("ASN popped from the queue: {}".format(asn))

            if asn is not None and asn in asn_results:
                logging.debug("ASN already in results: {}".format(asn))
                continue

            if asn is not None:

                asn_results.append(asn)

                asn_networks = get_networks(asn, asndb_file)

            if asn_networks is not None:
                for network in asn_networks:
                    network_queue.put(network)
            asn_queue.task_done()

        except queue.Empty:
            time.sleep(1)
            continue
        except Exception as e:
            logging.error(e, exc_info=True)
            pass


def network_worker(asndb_file, domain_queue, asn_queue, network_queue, address_queue, network_results, done):
    asndb_file = asndb_file

    while not done.is_set():
        try:
            network = network_queue.get(timeout=1)
            logging.debug("Network popped from the queue: {}".format(network))

            if network is not None and network in network_results:
                logging.debug("Network already in results: {}".format(network))
                continue

            if network is not None:
                network_results.append(network)

            network_queue.task_done()

        except queue.Empty:
            time.sleep(1)
            continue

        except Exception as e:
            logging.error(e, exc_info=True)
            pass


def signal_handler(signal, frame):
    """
    This method appeases drone.
    """
    print("Caught signal, exiting...")
    sys.exit(signal)


def get_asn(ip_addr, asndb_file):
    """
    Returns the Autonomous System number of a network IP address.
    Args:
        ip_addr: A network IP address.
        asndb_file: The ASN database file to perform lookups against.
    Returns:
        String: The Autonomous System number.
    """
    logging.debug("Attempting to find ASN for: {}".format(ip_addr))

    try:
        asndb = pyasn.pyasn(asndb_file)
        result = asndb.lookup(ip_addr)[0]
        logging.info("Found ASN: ASN{} - {}".format(result, ip_addr))
        return result
    except Exception as e:
        logging.error(e, exc_info=True)
        pass


def get_networks(asn, asndb_file):
    """
    Returns the network blocks of an Autonomous System number.
    Args:
        asn: An Autonomous System number.
        asndb_file: The ASN database file to perform lookups against.
    Returns:
        List: Network blocks in CIDR format.
    """
    logging.debug("Attempting to find networks for ASN: {}".format(asn))

    try:
        asndb = pyasn.pyasn(asndb_file)
        return asndb.get_as_prefixes(asn)
    except Exception as e:
        logging.error(e, exc_info=True)
        pass


def get_wildcard(resolver, domain):
    """
    Checks to see if a wildcard exists.
    Args:
        domain: Domain where we are checking the wildcard.
    Returns:
        String: Returns either the valid wildcard address or returns 0.0.0.0.
    """
    import random
    import string

    resolver = resolver
    random_len = random.randint(7, 12)
    random_str = ''.join(random.choice(string.ascii_lowercase) for i in range(random_len))
    fqdn = '.'.join([random_str, domain])

    ip_addr = None

    try:
        records = resolver.query(fqdn, "A")
        for record in records:
            ip_addr = record.address
            logging.debug("Found Wildcard Address: {}".format(ip_addr))
        return ip_addr
    except Exception as e:
        pass


def resolve_domain(resolver, domain, wild_cards):
    """
    Resolves the A records for a given domain.
    Args:
        domain: domain that we are looking for subdomains against.
    Returns:
        List: Return a list of IP addresses based on valid A records.
    """
    logging.debug("Attempting to resolve: {}".format(domain))
    resolver = resolver
    wildcard_addr = get_wildcard(resolver, domain)
    if wildcard_addr not in wild_cards:
        wild_cards.append(wildcard_addr)
    valid = []

    try:
        records = resolver.query(domain)
        for record in records:
            if record.address not in wild_cards:
                logging.info("Found subdomain: {} - {}".format(domain, record.address))
                valid.append(record.address)
            else:
                logging.debug("Wildcard found in list: {}".format(wild_cards))
        return valid
    except:
        pass


def get_rdns(ip):
    """
    Checks to see if a PTR record exists for a given IP address.
    Args:
        ip: IP address.
    Returns:
        String or None: PTR record if it exists.
    """
    logging.debug("Attempting to get RDNS for: {}".format(ip))

    try:
        address = dns.reversename.from_address(ip)
        records = dns.resolver.query(address, "PTR")

        for record in records:
            rdns = record.target
            logging.info("Found RDNS: {} - {}".format(str(rdns), ip))
        return str(rdns)
    except Exception as e:
        pass


def get_ips(network):
    """
    Gets the individual IP addresses in given network range.
    Args:
        network: network range in cidr notation.
    Returns:
        List of IP addresses.
    """
    logging.debug("Attempting to get IPs for network: {}".format(network))
    ip_addresses = []

    for ip in netaddr.IPNetwork(network):
        ip_addresses.append(str(ip))

    return ip_addresses


def report(domains, asns=None, networks=None, addresses=None, rdns=None):
    """
    Prints the sets of given domains, autonomous system numbers, networks, PTRs, and IP addresses if user wants it.
    Args:
        domains: set of domains gathered.
        asns: set of autonomous system numbers gathered.
        networks: set of network ranges gathered.
        addresses: set of IP addresses gathered.
        rdns: set of PTR records
    """
    if domains is not None:
        print_border("DOMAINS ({})".format(len(domains)))
        print("{}".format("\n".join(str(x) for x in domains)))

    if asns is not None:
        print_border("AUTONOMOUS SYSTEM NUMBERS ({})".format(len(asns)))
        print(*asns, sep="\n")

    if networks is not None:
        networks = netaddr.cidr_merge(list(networks))
        print_border("NETWORK RANGES ({})".format(len(networks)))
        print(*networks, sep="\n")

    if addresses is not None:
        print_border("IP ADDRESSES ({})".format(len(addresses)))
        print(*addresses, sep="\n")

    if rdns is not None:
        print_border("RDNS RECORDS ({})".format(len(rdns)))
        print(*rdns, sep="\n")


def print_border(text):
    """
    Prints a border around a given string.
    Args:
        text: A string of text to put a border around.
    """
    border = "*" * len(text)
    print(border)
    print(text)
    print(border)


def main():
    # parse the arguments provided to us
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True, help="domain or file with a list of domains")
    parser.add_argument("--asndb", required=True, help="latest asndb file")
    parser.add_argument("--subdomains", required=False, help="file of subdomains separate by newlines")
    parser.add_argument("--threads", required=False, type=int, help="number of threads to use")
    parser.add_argument("--nameservers", required=False, help="file of specific nameservers to use")
    parser.add_argument("--debug", type=int, required=False,
                        help="levels of verbosity: 1 - Informational, 2 - Debugging, 3 - Errors")
    parser.add_argument("--recursive", required=False, type=bool,
                        help="If set, valid subdomains will be added to domain queue")

    args = parser.parse_args()

    domain = args.domain
    asndb_file = args.asndb
    subdomains_file = args.subdomains
    threads = args.threads
    nameservers_file = args.nameservers
    debug = args.debug
    recursive = args.recursive

    signal.signal(signal.SIGINT, signal_handler)

    # initialize our work queues
    domain_queue = multiprocessing.JoinableQueue()
    asn_queue = multiprocessing.JoinableQueue()
    network_queue = multiprocessing.JoinableQueue()
    address_queue = multiprocessing.JoinableQueue()

    # initialize our result sets
    manager = multiprocessing.Manager()
    domain_results = manager.list()
    asn_results = manager.list()
    network_results = manager.list()
    address_results = manager.list()
    rdns_results = manager.list()
    wild_cards = manager.list()

    if threads is None:
        threads = 10

    if recursive is not None:
        recursive = True

    if debug == 1:
        logging.basicConfig(level=logging.INFO)
    elif debug == 2:
        logging.basicConfig(level=logging.DEBUG)
    elif debug == 3:
        logging.basicConfig(level=logging.ERROR)

    # check to see if argument is a file, if so, read it line for line and add to domains list
    if os.path.exists(domain):
        try:
            domains = [line.strip() for line in open(domain)]
        except IOError:
            logging.error("Failed to open {}".format(domain))
            sys.exit(1)
    else:
        domains = []
        domains.append(domain)

    # if a subdomains file was specified, attempt to open it and add it to the subdomains list
    if subdomains_file is not None:
        if os.path.exists(subdomains_file):
            try:
                subdomains = [line.strip() for line in open(subdomains_file)]
            except IOError:
                logging.error("Failed to open {}".format(subdomains_file))
                sys.exit(1)
        else:
            logging.error("File {} does not exist".format(subdomains_file))
            sys.exit(1)
    else:
        subdomains = []

    # check to see if asndb file exists
    if asndb_file is not None:
        if os.path.exists(asndb_file):
          pass
        else:
            logging.error("File {} does not exist".format(asndb_file))
            sys.exit(1)

    # if a nameservers file was specified, attempt to open it and add it to the nameservers list
    if nameservers_file is not None:
        if os.path.exists(nameservers_file):
            try:
                nameservers = [line.strip() for line in open(nameservers_file)]
            except IOError:
                logging.error("Failed to open {}".format(nameservers_file))
                sys.exit(1)
        else:
            logging.error("File {} does not exist".format(nameservers_file))
            sys.exit(1)
    else:
        # no nameservers file specified, let's use Google's
        nameservers = ["8.8.8.8", "8.8.4.4"]

    resolver = dns.resolver.Resolver()
    resolver.nameservers = nameservers

    domain_worker_threads = []
    asn_worker_threads = []
    network_worker_threads = []
    address_worker_threads = []

    done = manager.Event()
    done.clear()

    for domain in domains:
        domain_queue.put(domain)
        for sub in subdomains:
            fqdn = ".".join([sub, domain])
            domain_queue.put(fqdn)

    for domainWorker in range(threads):
        p = multiprocessing.Process(
            target=domain_worker,
            args=(resolver, recursive, subdomains, wild_cards, domain_queue,
                  asn_queue, network_queue, address_queue, domain_results, done))
        domain_worker_threads.append(p)
        p.start()

    for asnWorker in range(1,2):
        p = multiprocessing.Process(
            target=asn_worker,
            args=(asndb_file, domain_queue, asn_queue, network_queue, address_queue, asn_results, done))
        asn_worker_threads.append(p)
        p.start()

    for networkWorker in range(1,2):
        p = multiprocessing.Process(
            target=network_worker,
            args=(asndb_file, domain_queue, asn_queue, network_queue, address_queue, network_results, done))
        network_worker_threads.append(p)
        p.start()


    for addressWorker in range(1,2):
        p = multiprocessing.Process(
            target=address_worker,
            args=(asndb_file, domain_queue, asn_queue, network_queue, address_queue,
                  address_results, rdns_results, done))
        address_worker_threads.append(p)
        p.start()

    while domain_queue.qsize() > 0 or asn_queue.qsize() > 0 or address_queue.qsize() > 0 or network_queue.qsize() > 0:
        time.sleep(2)

    done.set()

    for p in domain_worker_threads:
        p.join(timeout=5)
    for p in asn_worker_threads:
        p.join(timeout=5)
    for p in network_worker_threads:
        p.join(timeout=5)
    for p in address_worker_threads:
        p.join(timeout=5)

    report(domains=domain_results,
           asns=asn_results,
           networks=network_results,
           addresses=address_results,
           rdns=rdns_results)


if __name__ == '__main__':
    main()
