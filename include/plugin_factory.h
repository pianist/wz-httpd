
#ifndef _RFifgbDHdbfgbFdfbHDGHDF_
#define _RFifgbDHdbfgbFdfbHDGHDF_

#include <map>
#include <wz_handler.h>
#include <wspp.hpp>

class Plugin_Factory
{
	typedef wzconfig::ROOT::PLUGINS::PLUGIN plugin_desc;
	std::list<Plugin*> items;
	std::map<std::string, void*> loaded_modules;
	void load_plugin(const plugin_desc &p_d);
public:
	void load_plugins();
	void unload_plugins();
	~Plugin_Factory();
	void handle(const Request *in, Response *out);
	void idle();

	void set_websocket_writer(Websocket_Writer *wswr);
	void remove_ws_key(const char *k);
	void handle_websocket_event(const char *k, const websocket_protocol_parser::incoming_event& e);
};

extern Plugin_Factory plugins;

#endif

