#ifndef __SPE_H__
#define __SPE_H__
#include "common.h"

typedef std::unordered_map<std::string, std::vector<std::pair<std::string, std::string>>> index_t;

class SessionPayloadExtractor{
private:
    std::string mCsvPath;
    std::string mPcapPath;
    index_t session_map;
    void init_session_index();
    void insert_payload_to_index();
public:
    SessionPayloadExtractor(std::string _csvPath, std::string _pcapPath);
    void save_session_payloads(std::string _savePath);
};

void pktHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
#endif