#include "common.h"
#include "spe.h"


int main(int argc, char** argv){
    std::string csvPath = argv[1];
    std::string pcapPath = argv[2];
    SessionPayloadExtractor spe(csvPath, pcapPath);
    spe.save_session_payloads(argv[3]);
    return 0;
}