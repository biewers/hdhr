#include <iostream>
#include <sys/socket.h>
#include "hdhomerun.h"

using namespace std;

struct hdhomerun_sock_t {
    int sock;
};

struct client_request_t {
    uint32_t ip_addr;
    uint16_t remote_port;
    uint32_t device_type;
    uint32_t device_id;
};

typedef char device_auth_t[25];
typedef char base_url_t[29];

hdhomerun_sock_t* create_udp_socket();
bool handle_udp_socket(hdhomerun_sock_t* hdsock);
bool recv_from_client(hdhomerun_sock_t* hdsock, client_request_t* request);
bool send_to_client(hdhomerun_sock_t* sock, uint32_t target_ip, uint16_t port, uint32_t device_type, uint32_t device_id, device_auth_t device_auth, base_url_t base_url);

bool create_tcp_socket(int* sock);
bool handle_tcp_socket(int sock);

uint32_t DEVICE_ID = 0x10b2c3d4;
device_auth_t DEVICE_AUTH = "randomrandomrandomrandom";
base_url_t BASE_URL = "http://192.168.0.168:8080";

int main()
{
    hdhomerun_sock_t* hdsock = create_udp_socket();
    if (!hdsock)
    {
        std::cerr << "Failed to create udp socket" << std::endl;
        return -1;
    }

    int sock;
    if (!create_tcp_socket(&sock))
    {
        std::cerr << "Failed to create tcp socket" << std::endl;
        return -1;
    }

    int max_sd = max(hdsock->sock, sock);

    fd_set readfds;
    while (true)
    {
        FD_ZERO(&readfds);
        FD_SET(hdsock->sock, &readfds);
        FD_SET(sock, &readfds);
        int activity = select(max_sd+1, &readfds, NULL, NULL, NULL);
        if (activity < 0 && errno != EINTR)
        {
            std::cout << "select error" << std::endl;
            break;
        }

        if (FD_ISSET(hdsock->sock, &readfds))
        {
            handle_udp_socket(hdsock);
        }

        if (FD_ISSET(sock, &readfds))
        {
            handle_tcp_socket(sock);
        }
    }

    return 0;
}

hdhomerun_sock_t* create_udp_socket()
{
    hdhomerun_sock_t *hdsock = hdhomerun_sock_create_udp();

    int flags = fcntl(hdsock->sock, F_GETFL);
    fcntl(hdsock->sock, F_SETFL, flags ^ O_NONBLOCK); // turn on blocking mode again

    if (!hdhomerun_sock_bind(hdsock, INADDR_ANY, HDHOMERUN_DISCOVER_UDP_PORT, 1))
    {
        std::cerr << "Failed to bind" << std::endl;
        hdhomerun_sock_destroy(hdsock);
        return nullptr;
    }

    std::cout << "Bind OK" << std::endl;

    return hdsock;
}

bool handle_udp_socket(hdhomerun_sock_t* hdsock)
{
    client_request_t request = {0};
    if (!recv_from_client(hdsock, &request))
    {
        std::cerr << "Failed to receive" << std::endl;
        hdhomerun_sock_destroy(hdsock);
        return false;
    }

    std::cout << "Recv from OK" << std::endl;
    std::cout << "IP: " << request.ip_addr << " "
                << "Port: " << request.remote_port << " "
                << "Device ID: " << request.device_id << " "
                << "Device type: " << request.device_type << std::endl;

    if (!send_to_client(hdsock, request.ip_addr, request.remote_port, HDHOMERUN_DEVICE_TYPE_TUNER, DEVICE_ID,
                        DEVICE_AUTH, BASE_URL))
    {
        std::cerr << "Failed to send" << std::endl;
        hdhomerun_sock_destroy(hdsock);
        return false;
    }

    std::cout << "Send to OK" << std::endl;

    return true;
}

bool recv_from_client(hdhomerun_sock_t* hdsock, client_request_t* request)
{
    hdhomerun_pkt_t rx_pkt;
    hdhomerun_pkt_reset(&rx_pkt);

    uint32_t remote_addr;
    uint16_t remote_port;
    size_t length = rx_pkt.limit - rx_pkt.end;
    if (!hdhomerun_sock_recvfrom(hdsock, &remote_addr, &remote_port, rx_pkt.end, &length, 0))
    {
        return false;
    }

    rx_pkt.end += length;

    for (uint8_t* i = rx_pkt.start; i < rx_pkt.end; i++) {
        printf("%02x ", *i);
    }
    printf("\n");

    uint16_t type;
    if (hdhomerun_pkt_open_frame(&rx_pkt, &type) <= 0)
    {
        return false;
    }
    if (type != HDHOMERUN_TYPE_DISCOVER_REQ)
    {
        return false;
    }

    memset(request, 0, sizeof(client_request_t));
    request->ip_addr = remote_addr;
    request->remote_port = remote_port;

    while (1)
    {
        uint8_t tag;
        size_t len;
        uint8_t *next = hdhomerun_pkt_read_tlv(&rx_pkt, &tag, &len);
        if (!next)
        {
            break;
        }

        std::cout << "Tag " << (int) tag << std::endl;

        switch (tag)
        {
            case HDHOMERUN_TAG_DEVICE_TYPE:
                if (len != 4)
                {
                    break;
                }
                request->device_type = hdhomerun_pkt_read_u32(&rx_pkt);
                break;

            case HDHOMERUN_TAG_DEVICE_ID:
                if (len != 4)
                {
                    break;
                }
                request->device_id = hdhomerun_pkt_read_u32(&rx_pkt);
                break;

            default:
                break;
        }

        rx_pkt.pos = next;
    }

    return true;
}

bool send_to_client(
        hdhomerun_sock_t* sock,
        uint32_t target_ip,
        uint16_t remote_port,
        uint32_t device_type,
        uint32_t device_id,
        device_auth_t device_auth,
        base_url_t base_url
)
{
    hdhomerun_pkt_t tx_pkt;
    hdhomerun_pkt_reset(&tx_pkt);

    hdhomerun_pkt_write_u8(&tx_pkt, HDHOMERUN_TAG_DEVICE_TYPE);
    hdhomerun_pkt_write_var_length(&tx_pkt, 4);
    hdhomerun_pkt_write_u32(&tx_pkt, device_type);
    hdhomerun_pkt_write_u8(&tx_pkt, HDHOMERUN_TAG_DEVICE_ID);
    hdhomerun_pkt_write_var_length(&tx_pkt, 4);
    hdhomerun_pkt_write_u32(&tx_pkt, device_id);
    hdhomerun_pkt_write_u8(&tx_pkt, HDHOMERUN_TAG_DEVICE_AUTH_STR);
    hdhomerun_pkt_write_var_length(&tx_pkt, sizeof(device_auth_t)-1);
    hdhomerun_pkt_write_mem(&tx_pkt, device_auth, sizeof(device_auth_t)-1);
    hdhomerun_pkt_write_u8(&tx_pkt, HDHOMERUN_TAG_BASE_URL);
    hdhomerun_pkt_write_var_length(&tx_pkt, sizeof(base_url_t)-1);
    hdhomerun_pkt_write_mem(&tx_pkt, base_url, sizeof(base_url_t)-1);
    hdhomerun_pkt_seal_frame(&tx_pkt, HDHOMERUN_TYPE_DISCOVER_RPY);

    return hdhomerun_sock_sendto(sock, target_ip, remote_port, tx_pkt.start, tx_pkt.end - tx_pkt.start, 0);
}

bool create_tcp_socket(int* sock)
{
    if ((*sock = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        std::cerr << "Socket creation failed: " << errno << std::endl;
        return false;
    }

    //set master socket to allow multiple connections, this is just a good habit, it will work without this
    int opt = 1;
    if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char*) &opt, sizeof(opt)) < 0)
    {
        std::cerr << "Socket option failed: " << errno << std::endl;
        return false;
    }

    sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(*sock, (const sockaddr*) &address, (socklen_t) sizeof(address)) < 0)
    {
        std::cerr << "Socket bind failed: " << errno << std::endl;
        return false;
    }

    if (listen(*sock, 3) < 0)
    {
        std::cerr << "Socket listen failed: " << errno << std::endl;
        return false;
    }

    return true;
}

bool handle_tcp_socket(int sock)
{
    int newSocket;
    sockaddr_in address = {0};
    socklen_t addrlen = sizeof(address);

    if ((newSocket = accept(sock, (sockaddr*) &address, &addrlen))<0)
    {
        std::cerr << "Accept failed" << std::endl;
        return false;
    }

    printf("New connection, socket fd is %d, ip is: %s, port: %d\n",
           newSocket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

    return true;
}