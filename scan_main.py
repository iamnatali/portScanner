import threading
import socket
import os
import ssl
import binascii
import argparse
import struct
import time


def udp_portscan_1(port, target):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if os.name == 'nt':
        proto = socket.IPPROTO_IP
    else:
        proto = socket.IPPROTO_ICMP
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        sniffer.bind((target, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)
    except Exception:
        print("binding went wrong.please check you have all rights and your ip settings are OK")
    #if os.name == 'nt':
    #    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        try:
            client.sendto("".encode('utf_8'), (target, port))
            sniffer.settimeout(1)
            data, addr = sniffer.recvfrom(65218)
            if data[9] == 1:
                print('Port {} closed'.format(port))
            else:
                print('Port {} open'.format(port))
        except socket.timeout:
            print('Port {}: open'.format(port))
        except Exception:
            print("binding went wrong.please check you have all rights and your ip settings are OK")
        finally:
            sniffer.close()
    finally:
        client.close()
    #if os.name == 'nt':
    #   sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


def check_http(port, target):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((target, port))
        request = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" % target
        client.send(request.encode())
        client.settimeout(1)
        try:
            ans = client.recv(4096)
            if ans[0:4] == b'HTTP':
                return True
        except socket.timeout:
            return False
        except WindowsError:
            return False
        except Exception as e:
            print(str(port) + str(e))
            return False


def check_smtp(port, target):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((target, port))
        client.settimeout(1)
        try:
            client = ssl.wrap_socket(client)
            data = client.recv(1024)
        except socket.timeout:
            return False
        except WindowsError:
            return False
        except Exception as e:
            print(str(port) + str(e))
            return False
        if data[0:3] == b'220':
            client.send(('EHLO natali\n').encode())
            client.settimeout(1)
            try:
                client.recv(1024)
            except socket.timeout:
                return False
            except WindowsError:
                return False
            return True


def check_pop3(port, target):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((target, port))
        client.settimeout(1)
        try:
            client = ssl.wrap_socket(client)
            client.send(('USER natali' + '\n').encode())
            recv_data = client.recv(65535).decode()
            if recv_data[0:3] == '+OK':
                return True
        except socket.timeout:
            return False
        except WindowsError:
            return False
        except Exception as e:
            print(str(port) + str(e))
            return False


def tcp_portscan(port, target, toDig):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        connection = s.connect((target, port))
        res_str = "Port :{} is open".format(port)
        if toDig:
            if check_http(port, target):
                res_str += ' http'
            else:
                if check_smtp(port, target):
                    res_str += ' smtp'
                if check_pop3(port, target):
                    res_str += " pop3"
        print(res_str)
        try:
            connection.close()
        except Exception:
            pass
    except socket.timeout:
        pass
    except Exception as e:
        print(str(port)+" "+str(e))


def check_dns(port, target):
    message = "AA AA 01 00 00 01 00 00 00 00 00 00 " \
              "07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01"
    message = message.replace(" ", "").replace("\n", "")
    server_address = (target, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
        res = binascii.hexlify(data).decode("utf-8")
        if res[0:4].lower() == 'aaaa':
            return True
        else:
            return False
    except socket.timeout:
        return False
    except Exception as e:
        print(e)
        print('dns exception'+str(port)+' '+str(target))
    finally:
        sock.close()
    return True


def check_sntp(port, target):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = '\x1b' + 47 * '\0'
    client.sendto(data.encode('utf-8'), (target, port))
    client.settimeout(1)
    try:
        data, address = client.recvfrom(1024)
    except socket.timeout:
        return False
    except Exception as e:
        print(e)
        print('sntp exception'+str(port)+' '+str(target))
    if data:
        try:
            t = struct.unpack('!12I', data)[10]
            t1 = time.ctime(t)
            return True
        except struct.error:
            return False


def udp_portscan(port, target):
    if check_dns(port, target):
        print("Port :{} is open dns".format(port))
    if check_sntp(port, target):
        print("Port :{} is open sntp".format(port))


#checks for known programms
def udp_scan(start, end, target):
    ports = range(start, end+1)
    for p in ports:
        t = threading.Thread(target=udp_portscan, kwargs={'port': p, 'target': target})
        t.start()


def tcp_scan(start, end, target):
    ports = range(start, end+1)
    for p in ports:
        t = threading.Thread(target=tcp_portscan, kwargs={'port': p, 'target': target, 'toDig': True})
        t.start()


def tcp1_scan(start, end, target):
    ports = range(start, end+1)
    for p in ports:
        t = threading.Thread(target=tcp_portscan, kwargs={'port': p, 'target': target, 'toDig': False})
        t.start()


def udp1_scan(start, end, target):
    ports = range(start, end + 1)
    for p in ports:
        t = threading.Thread(target=udp_portscan_1, kwargs={'port': p, 'target': target})
        t.start()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='help',
                        default=argparse.SUPPRESS,
                        help='show this message and quit')
    parser.add_argument(dest='protocol', choices=['udp', 'tcp', 'udp1', 'tcp1'], help='type of ports to scan')
    parser.add_argument(dest='target', type=str, nargs=1, help='target host')
    parser.add_argument(dest='start', type=int, nargs=1, help='start number of ports range')
    parser.add_argument(dest='end', type=int, nargs=1, help='end number of ports range')
    res = parser.parse_args()
    if res.protocol == 'tcp':
        tcp_scan(res.start[0], res.end[0], res.target[0])
    elif res.protocol == 'tcp1':
        tcp1_scan(res.start[0], res.end[0], res.target[0])
    elif res.protocol == 'udp':
        udp_scan(res.start[0], res.end[0], res.target[0])
    elif res.protocol == 'udp1':
        udp1_scan(res.start[0], res.end[0], res.target[0])
