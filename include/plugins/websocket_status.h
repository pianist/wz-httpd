#ifndef _server_ws_status_plugin_09876543_
#define _server_ws_status_plugin_09876543_

#include <wz_handler.h>
#include <string>
#include <set>

class SP_server_websocket_status : public Plugin
{
	std::set<std::string> ws_keys;

public:
	SP_server_websocket_status();
	~SP_server_websocket_status();
	int set_param(const char *param) { return 0; };
	void handle(const Request *in, Response *out);
	void idle();
	void remove_ws_key(const char *k);
	void handle_ws_string(const char *k, const char *s);
};

#endif

