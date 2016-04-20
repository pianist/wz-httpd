
#ifndef _REQUEST_H_DFHDFDHSDFHEFDHDHDGHDF_
#define _REQUEST_H_DFHDFDHSDFHEFDHDHDGHDF_

#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_HEADER_ITEMS 32

struct Request
{
	struct header_item
	{
		const char *key;
		const char *value;
	};
	struct in_addr ip;
	enum { REQUEST_UNDEFINED, REQUEST_GET, REQUEST_POST, REQUEST_HEAD } method;
	int major;
	int minor;
	int keep_alive;
	const char *uri_path;
	const char *uri_params;
	const char *cookie;
	const char *user_agent;
	const char *x_forwarded_for;
	const char *referer;
	const char *content_type;
	int content_len;

	header_item header_items[MAX_HEADER_ITEMS];
	char *post_body;
	const char *host;

	const char *x_real_ip;

	const char *upgrade;
	const char *connection;
	const char *sec_websocket_key;
	const char *sec_websocket_protocol;
	const char *sec_websocket_version;
	const char *sec_websocket_extensions;
};

struct Response
{
	int status;
	int can_cache;
	const char *content_type;
	const char *location;
	const char *set_cookie;
	const char *set_cookie2;
	const void *body;
	int body_len;

	const char *sec_websocket_accept;
	const char *upgrade;
	const char *connection;

	const char *ws_key;
};

struct Websocket_Writer
{
	virtual bool write_string(const char *ws_key, const char *s) = 0;
	virtual bool write_ping(const char *ws_key, int is_pong = 0) = 0;
	virtual bool write_close(const char *ws_key, unsigned code = 1000) = 0;
};

class Plugin
{
public:
	Websocket_Writer *ws_writer;

	Plugin(): ws_writer(0) {};
	virtual ~Plugin() {};
	virtual int set_param(const char *param) = 0;
	virtual void handle(const Request *in, Response *out) = 0;
	virtual void idle() {};

	virtual void remove_ws_key(const char *k) {};
	virtual void handle_ws_string(const char *k, const char *s) {};
	virtual void handle_ws_binary(const char *k, const void *d, size_t sz) {};
};

#endif

