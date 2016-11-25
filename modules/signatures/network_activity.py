from lib.cuckoo.common.abstracts import Signature

from common.win32api import detect

class NetworkActivity(Signature):
    name = "performs_network_activity"
    description = "Process that sends and receives information over the network."
    severity = 1
    authors = ["Matthew Bradbury <matt-bradbury(at)live(dot)co(dot)uk>"]
    category = ["API Search"]

    references = ["http://msdn.microsoft.com/en-us/library/windows/desktop/ms741394%28v=vs.85%29.aspx"]

    apis = {"accept", "AcceptEx", "bind", "closesocket", "connect", "ConnectEx", "DisconnectEx", 
            "EnumProtocols", "freeaddrinfo", "FreeAddrInfoW", "FreeAddrInfoEx", "gai_strerror", 
            "GetAcceptExSockaddrs", "GetAddressByName", "getaddrinfo", "GetAddrInfoEx", "GetAddrInfoExCancel", 
            "GetAddrInfoExOverlappedResult", "GetAddrInfoW", "gethostbyaddr", "gethostbyname", "gethostname", 
            "GetNameByType", "getnameinfo", "GetNameInfoW", "getpeername", "getprotobyname",
            "getprotobynumber", 
            "getservbyname", "getservbyport", "GetService", "getsockname", "getsockopt", "GetTypeByName", 
            "htonl", "htons", "inet_addr", "inet_ntoa", "InetNtop", "InetPton", "ioctlsocket", "listen", 
            "ntohl", "ntohs", "recv", "recvfrom", "RIOCloseCompletionQueue", "RIOCreateCompletionQueue", 
            "RIOCreateRequestQueue", "RIODequeueCompletion", "RIODeregisterBuffer", "RIONotify", 
            "RIOReceive", "RIOReceiveEx", "RIORegisterBuffer", "RIOResizeCompletionQueue",
            "RIOResizeRequestQueue", "RIOSend", "RIOSendEx", "select", "send", "sendto", "SetAddrInfoEx", 
            "SetService", "SetSocketMediaStreamingMode", "setsockopt", "shutdown", "socket", "TransmitFile", 
            "TransmitPackets", "WSAAccept", "WSAAddressToString", "WSAAsyncGetHostByAddr",
            "WSAAsyncGetHostByName", "WSAAsyncGetProtoByName", "WSAAsyncGetProtoByNumber", 
            "WSAAsyncGetServByName", "WSAAsyncGetServByPort", "WSAAsyncSelect", "WSACancelAsyncRequest", 
            "WSACancelBlockingCall", "WSACleanup", "WSACloseEvent", "WSAConnect", "WSAConnectByList", 
            "WSAConnectByName", "WSACreateEvent", "WSADeleteSocketPeerTargetName", "WSADuplicateSocket", 
            "WSAEnumNameSpaceProviders", "WSAEnumNameSpaceProvidersEx", "WSAEnumNetworkEvents", 
            "WSAEnumProtocols", "WSAEventSelect", "__WSAFDIsSet", "WSAGetLastError", "WSAGetOverlappedResult", 
            "WSAGetQOSByName", "WSAGetServiceClassInfo", "WSAGetServiceClassNameByClassId", "WSAHtonl", 
            "WSAHtons", "WSAImpersonateSocketPeer", "WSAInstallServiceClass", "WSAIoctl", "WSAIsBlocking", 
            "WSAJoinLeaf", "WSALookupServiceBegin", "WSALookupServiceEnd", "WSALookupServiceNext",
            "WSANSPIoctl", 
            "WSANtohl", "WSANtohs", "WSAPoll", "WSAQuerySocketSecurity", "WSAProviderConfigChange", "WSARecv", 
            "WSARecvDisconnect", "WSARecvEx", "WSARecvFrom", "WSARecvMsg", "WSARemoveServiceClass",
            "WSAResetEvent", "WSARevertImpersonation", "WSASend", "WSASendDisconnect", "WSASendMsg", 
            "WSASendTo", "WSASetBlockingHook", "WSASetEvent", "WSASetLastError", "WSASetService", 
            "WSASetSocketPeerTargetName", "WSASetSocketSecurity", "WSASocket", "WSAStartup", 
            "WSAStringToAddress", "WSAUnhookBlockingHook", "WSAWaitForMultipleEvents"
           }

    def run(self, results):
        return detect(self, results)
        

