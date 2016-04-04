#include <plugins/websocket_status.h>
#include <coda/logger.h>
#include <string.h>

SP_server_websocket_status::SP_server_websocket_status()
{
}

SP_server_websocket_status::~SP_server_websocket_status()
{
}

void SP_server_websocket_status::handle(const Request *in, Response *out)
{
	if (!strncmp(in->uri_path, "/server_websocket_status", 24))
	{
		log_notice("%s /server_websocket_status", inet_ntoa(in->ip));
		switch_to_websocket(in, out);

		if (out->ws_key)
		{
			ws_keys.insert(out->ws_key);
			log_notice("created ws with key %s", out->ws_key);
		}
	} 
}

void SP_server_websocket_status::idle()
{
	char buf[1024];
	snprintf(buf, 1024, "tesing: %u", (unsigned)time(0));

	for (std::set<std::string>::const_iterator it = ws_keys.begin(); it != ws_keys.end(); ++it)
	{
//		log_notice("Doing push to %s ws", it->c_str());
		ws_writer->write_ping(it->c_str());
//		ws_writer->write_string(it->c_str(), buf);
//		ws_writer->write_string(it->c_str(), "qwertyuiopoiuytrewqwertyuiopoiuytrewertyuioasdfghjkl;lkjhgfdsdfghjklmnbvcxzxcvbnm,mnbvc345678909876543456789098765434567890987654345678909876erfgdertyuioiuytrewertyuioiuytrewertyuijhgfdsdfghjklkjhgfdsdfghjkkjhgf");
	}
}

void SP_server_websocket_status::handle_ws_string(const char *k, const char *s)
{
	log_notice("String came to %s: %s", k, s);
}

void SP_server_websocket_status::remove_ws_key(const char *k)
{
	ws_keys.erase(k);
}

