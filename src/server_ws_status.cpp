#include <plugins/websocket_status.h>
#include <coda/logger.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/sha.h>
#include <coda/base64.h>

SP_server_websocket_status::SP_server_websocket_status()
{
}

SP_server_websocket_status::~SP_server_websocket_status()
{
}

bool SP_server_websocket_status::switch_to_websocket(const Request *in, Response *out)
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

	coda_base64_encode((char*)&digest, SHA_DIGEST_LENGTH, sec_ws_accept, 250);

	out->status = 101;
	out->ws_key = in->sec_websocket_key;
	out->upgrade = "WebSocket";
	out->connection = "Upgrade";
	out->sec_websocket_accept = sec_ws_accept;
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
	struct timeval _tmval;
	gettimeofday(&_tmval, 0);
	snprintf(buf, 1024, "tesing: %u.%u", (unsigned)_tmval.tv_sec, (unsigned)_tmval.tv_usec);

	for (std::set<std::string>::const_iterator it = ws_keys.begin(); it != ws_keys.end(); ++it)
	{
		log_notice("Doing push to %s ws", it->c_str());
		ws_writer->write_ping(it->c_str());
		ws_writer->write_string(it->c_str(), buf);
		ws_writer->write_string(it->c_str(), "qwertyuiopoiuytrewqwertyuiopoiuytrewertyuioasdfghjkl;lkjhgfdsdfghjklmnbvcxzxcvbnm,mnbvc345678909876543456789098765434567890987654345678909876erfgdertyuioiuytrewertyuioiuytrewertyuijhgfdsdfghjklkjhgfdsdfghjkkjhgf");
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

