#include <wz-httpd.h>
#include <stdexcept>
#include <plugins/server_status.h>
#include <plugins/websocket_status.h>
#include <dlfcn.h>
#include <openssl/sha.h>
#include <coda/base64.h>

bool Plugin::switch_to_websocket(const Request *in, Response *out)
{
	if (!in->upgrade) return false;
	if (!in->sec_websocket_key) return false;

	size_t k_len = strlen(in->sec_websocket_key);
	if (k_len > 100) return false;

	char buf[256];
	size_t buf_sz = k_len;
	strcpy(buf, in->sec_websocket_key);
	char *end_buf = strcpy(buf + buf_sz, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
	end_buf += 36;

	unsigned char digest[SHA_DIGEST_LENGTH];
	SHA1((unsigned char*)buf, end_buf - buf, (unsigned char*)&digest);

	base64_encode((char*)&digest, SHA_DIGEST_LENGTH, sec_ws_accept, 250);

	out->status = 101;
	out->ws_key = in->sec_websocket_key;
	out->upgrade = "WebSocket";
	out->connection = "Upgrade";
	out->sec_websocket_accept = sec_ws_accept;
}

Plugin_Factory plugins;

typedef Plugin* (*plugin_get_instance_proc)();

void Plugin_Factory::load_plugin(const plugin_desc &p_d)
{
	if (p_d.library.empty())
	{
		if (p_d.name == "server_status")
		{
			Plugin *p = new SP_server_status();
			if (p->set_param(p_d.params.c_str()) == -1)
			{
				char errbuf[1024];
				snprintf(errbuf, 1024, "cannot load module %s", p_d.library.c_str());
				throw std::logic_error(errbuf);
			}
			items.push_back(p);
		}
		else if (p_d.name == "server_websocket_status")
		{
			Plugin *p = new SP_server_websocket_status();
			if (p->set_param(p_d.params.c_str()) == -1)
			{
				char errbuf[1024];
				snprintf(errbuf, 1024, "cannot load module %s", p_d.library.c_str());
				throw std::logic_error(errbuf);
			}
			items.push_back(p);
		}
		else
		{
			log_crit("unknown internal plugin: %s", p_d.name.c_str());
			throw std::logic_error("cannot load unknown internal plugin");
		}
	}
	else
	{
		std::map<std::string, void*>::const_iterator mod_iter;
		mod_iter = loaded_modules.find(p_d.library);

		void *mylib = 0;
		if (mod_iter != loaded_modules.end())
		{
			mylib = mod_iter->second;
		}
		else
		{
			log_info("loading library %s", p_d.library.c_str());
			mylib = dlopen(p_d.library.c_str(), 0x00002);
			log_info("loaded library %s", p_d.library.c_str());
			if (mylib == 0)
			{
				char errbuf[1024];
				snprintf(errbuf, 1024, "cannot load library %s: %s", p_d.library.c_str(), dlerror());
				throw std::logic_error(errbuf);
			}
			loaded_modules[p_d.library] = mylib;
		}

		plugin_get_instance_proc get_proc = 0;
		*((void**)(&get_proc)) = dlsym(mylib, "get_plugin_instanse");

		const char *error = dlerror();
		if (error != 0)
		{
			char errbuf[1024];
			snprintf(errbuf, 1024, "cannot find symbol get_plugin_instanse() in library %s: %s", p_d.library.c_str(), error);
			throw std::logic_error(errbuf);
		}

		Plugin *myplugin = get_proc();
		if (myplugin == 0)
		{
			char errbuf[1024];
			snprintf(errbuf, 1024, "library %s was loaded, but get_plugin_instanse() returned NULL, can't load plugin!", p_d.library.c_str());
			throw std::logic_error(errbuf);
		}
		//message(0, "got instance");

		if (myplugin->set_param(p_d.params.c_str()) == -1)
		{
			char errbuf[1024];
			snprintf(errbuf, 1024, "cannot load module %s", p_d.library.c_str());
			throw std::logic_error(errbuf);
		}
		items.push_back(myplugin);
		//message(0, "all done with plugin");
	}
}

void Plugin_Factory::load_plugins()
{
	std::list<plugin_desc>::iterator pdi;
	for (pdi = cfg->r.plugins.items.begin(); pdi != cfg->r.plugins.items.end(); pdi++)
	{
		log_info("loading plugin %s", pdi->name.c_str());
		load_plugin(*pdi);
		log_info("loaded plugin %s", pdi->name.c_str());
	}
}

void Plugin_Factory::unload_plugins()
{
	std::list<Plugin*>::iterator pi;
	for (pi = items.begin(); pi != items.end(); pi++)
	{
		delete *pi;
	}
	items.clear();

	std::map<std::string, void*>::iterator li;
	for (li = loaded_modules.begin(); li != loaded_modules.end(); li++)
	{
		dlclose(li->second);
	}

	loaded_modules.clear();
}

Plugin_Factory::~Plugin_Factory()
{
	unload_plugins();
}

void Plugin_Factory::handle(const Request *in, Response *out)
{
	std::list<Plugin*>::iterator pi;
	for (pi = items.begin(); (pi != items.end()) && !out->status; pi++) (*pi)->handle(in, out);
}

void Plugin_Factory::idle()
{
	std::list<Plugin*>::iterator pi;
	for (pi = items.begin(); pi != items.end(); pi++) (*pi)->idle();
}

void Plugin_Factory::remove_ws_key(const char *k)
{
	std::list<Plugin*>::iterator pi;
	for (pi = items.begin(); pi != items.end(); pi++) (*pi)->remove_ws_key(k);
}

void Plugin_Factory::handle_websocket_event(const char *k, const websocket_protocol_parser::incoming_event &e)
{
	if (e.et == ET_CLOSE)
	{
		remove_ws_key(k);
	}
	else if (e.et == ET_STRING)
	{
		std::list<Plugin*>::iterator pi;
		for (pi = items.begin(); pi != items.end(); pi++) (*pi)->handle_ws_string(k, e.data.c_str());
	}
	else if (e.et == ET_BINARY)
	{
		std::list<Plugin*>::iterator pi;
		for (pi = items.begin(); pi != items.end(); pi++) (*pi)->handle_ws_binary(k, e.data.data(), e.data.size());
	}
}

void Plugin_Factory::set_websocket_writer(Websocket_Writer *wswr)
{
	std::list<Plugin*>::iterator pi;
	for (pi = items.begin(); pi != items.end(); pi++) (*pi)->ws_writer = wswr;
}


