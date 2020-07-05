#ifndef CMD_CONFIG
#define CMD_CONFIG

#include <string>

using namespace std;
static const std::string APPLICATION_ID = "b826359c-06f8-425e-8ec3-50a97a418916";

std::string get_appid() {
	return APPLICATION_ID;
}

#endif