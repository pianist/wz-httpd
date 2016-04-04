#ifndef _TALKER_H_31415926_
#define _TALKER_H_31415926_

#include <wzconfig.h>
#include <wz_handler.h>
#include <map>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <string>
#include <wspp.hpp>

class Websocket_Writer_Impl : public Websocket_Writer
{
public:
	bool write_string(const char *ws_key, const char *s);
	bool write_ping(const char *ws_key, int is_pong = 0);
	bool write_close(const char *ws_key, unsigned code = 1000);
};

extern Websocket_Writer *global_ws_writer;

class talker
{
	struct in_addr ip;
	time_t last_access;
	size_t cur_header;
	int fd;
	enum { R_UNDEFINED, R_READ_REQUEST_LINE, R_READ_HEADER, R_READ_POST_BODY, R_HANDLE, R_REPLY, R_WEBSOCKET, R_CLOSE } state;
// buffer stuff
	char *buffer;
	char *buffer_cur_read;
	char *buffer_cur_write;
// post body read stuff
	int readed_bytes;
// response & request
	Response *response;
	Request *request;
	std::string ws_key;
// private methods
	char *get_line();

	websocket_protocol_parser wspp;
	void read_websocket();

	void do_request_line(char *s);
	void do_header_line(char *s);
	void do_handle();
	void do_reply();
public:
	talker();
	void init(int client_fd, const struct in_addr &addr);
	void handle();
	void reset(int dont_close = 0);
	void done();
	bool is_timeout(const time_t &t);
	int get_fd() { return fd; };
	const std::string& get_ws_key() const { return ws_key; }
};

extern std::map<int, talker> wz_talkers;

#endif

