#include "spe.h"

SessionPayloadExtractor::SessionPayloadExtractor(std::string _csvPath, std::string _pcapPath){
    this->mCsvPath = _csvPath;
    this->mPcapPath = _pcapPath;
    this->init_session_index();
    this->insert_payload_to_index();
}

void SessionPayloadExtractor::save_session_payloads(std::string _savePath){
    for(auto it=this->session_map.begin(); it!=this->session_map.end(); it++){
        for(auto it2=it->second.begin(); it2!=it->second.end(); it2++){
            std::string time_info = "";
            for(char& c : it2->first){
                if(c == '-' || c == ':' || c == ' '){
                    continue;
                } else {
                    time_info += c;
                }
            }
            std::ofstream ofs(_savePath+"/"+it->first+"_"+time_info+".json");
            if (ofs.fail()){
                std::cerr << "Error while writing result !!" << std::endl;
                exit(1);
            }
            ofs << it2->second;
            ofs.close();
        }
    }
}

void SessionPayloadExtractor::init_session_index(){
    std::ifstream csvFile;
    csvFile.open(this->mCsvPath);
    if(csvFile.is_open()){
        std::string line;
        getline(csvFile, line);
        std::istringstream ss(line);
        std::string splitBuffer;
        int columnIdx = 0;
        std::unordered_map<std::string, int> columnMap;
        while(getline(ss, splitBuffer, ',')){
            ltrim(splitBuffer);
            rtrim(splitBuffer);
            columnMap[splitBuffer] = columnIdx;
            columnIdx++;
        }
        while(!csvFile.eof()){
            std::vector<std::string> splitData;
            getline(csvFile, line);
            if(line == ""){
                break;
            }
            std::istringstream ss(line);
            while(getline(ss, splitBuffer, ',')){
                ltrim(splitBuffer);
                rtrim(splitBuffer);
                splitData.push_back(splitBuffer);
            }
            std::string label = splitData[columnMap["Label"]];
            if (!(label.rfind("Benign", 0) == 0) && !(label.rfind("Transfer", 0) == 0)){
                continue;
            }
            std::string flow_id = splitData[columnMap["pr"]]+"_"+splitData[columnMap["sa"]]+"_"+splitData[columnMap["sp"]]+"_"+splitData[columnMap["da"]]+"_"+splitData[columnMap["dp"]];
            std::string ts = splitData[columnMap["ts"]];
            std::string te = splitData[columnMap["te"]];
            session_map[flow_id].push_back(std::make_pair(ts + "_" + te, ""));
        }
    }
    for(auto it=session_map.begin(); it != session_map.end(); it++){
        sort(it->second.begin(), it->second.end());
    }
}

void SessionPayloadExtractor::insert_payload_to_index(){
    char errbuf[PCAP_ERRBUF_SIZE]; 
    struct pcap_pkthdr *header;
    const unsigned char *pkt;
    pcap_t* pcap = pcap_open_offline(this->mPcapPath.c_str(), errbuf);
    if(pcap == NULL){
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        exit(1);
    }
    if(pcap_loop(pcap, 0, pktHandler, (u_char*)&this->session_map)<0){
        std::cout << "pcap_loop() failed" << pcap_geterr(pcap);
        exit(1);
    }
}

void pktHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    index_t *sessionMap = (index_t *) userData;
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    std::string ptc;
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    ethernetHeader = (struct ether_header*)packet;
    char timeBuf[20];
    strftime(timeBuf, 20, "%Y-%m-%d %H:%M:%S", localtime(&pkthdr->ts.tv_sec));
    std::string td = std::string(timeBuf);

    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

        if (ipHeader->ip_p == IPPROTO_TCP || ipHeader->ip_p == IPPROTO_UDP) {
            if(ipHeader->ip_p== IPPROTO_TCP){
                ptc = "TCP";
            } else {
                ptc = "UDP";
            }
            tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);
            data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

            std::string flow_id = ptc+"_"+std::string(sourceIp)+"_"+std::to_string(sourcePort)+"_"+std::string(destIp)+"_"+std::to_string(destPort);
            std::string flow_id_inv = ptc+"_"+std::string(destIp)+"_"+std::to_string(destPort)+"_"+std::string(sourceIp)+"_"+std::to_string(sourcePort);
            bool is_find = false;
            if (sessionMap->find(flow_id) != sessionMap->end()){
                for(auto it = (*sessionMap)[flow_id].begin(); it != (*sessionMap)[flow_id].end(); it++){
                    std::istringstream ss(it->first);
                    std::string splitBuffer;
                    getline(ss, splitBuffer, '_');
                    std::string ts = splitBuffer;
                    getline(ss, splitBuffer, '_');
                    std::string te = splitBuffer;
                    if(ts <= td && td <= te){
                        it->second = it->second+std::string(reinterpret_cast<const char *>(&data), dataLength);
                        is_find = true;
                        break;
                    }
                }
            }
            if (!is_find && (sessionMap->find(flow_id_inv) != sessionMap->end())){
                for(auto it = (*sessionMap)[flow_id_inv].begin(); it != (*sessionMap)[flow_id_inv].end(); it++){
                    std::istringstream ss(it->first);
                    std::string splitBuffer;
                    getline(ss, splitBuffer, '_');
                    std::string ts = splitBuffer;
                    getline(ss, splitBuffer, '_');
                    std::string te = splitBuffer;
                    if(ts <= td && td <= te){
                        it->second = it->second+static_cast<std::string>(reinterpret_cast<const char *>(data));
                        is_find = true;
                        break;
                    }
                }
            }
        }
    }
}