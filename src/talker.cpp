#include <wz-httpd.h>
#include <errno.h>
#include <time.h>
#include <config.h>
#include <string.h>

#if defined(MODEL_FREEBSD_KQUEUE)
#include <sys/event.h>
#elif defined(MODEL_LINUX_EPOLL)
#include <sys/epoll.h>
#else
#error "Unknown model!"
#endif

#define WZ_BUFFER_SIZE 8192

std::map<int, talker> wz_talkers;
std::map<std::string, int> wz_ws_keys;

bool Websocket_Writer_Impl::write_string(const char *ws_key, const char *s)
{
	std::map<std::string, int>::const_iterator fd_it = wz_ws_keys.find(ws_key);
	if (fd_it == wz_ws_keys.end()) return false;

	std::map<int, talker>::const_iterator talker_it = wz_talkers.find(fd_it->second);
	if (talker_it == wz_talkers.end()) return false;
	if (talker_it->second.get_ws_key() != ws_key) return false;

	int fd = fd_it->second;
	size_t sz_s = strlen(s);

	if (sz_s < 126)
	{
		unsigned char buf[2];
		buf[0] = 0x81;
		buf[1] = (unsigned char)sz_s;
		if (write(fd, buf, 2) != 2) wz_talkers[fd].reset();
		if (write(fd, s, sz_s) != sz_s) wz_talkers[fd].reset();
	}
	else if (sz_s < 65537)
	{
		unsigned char buf[4];
		uint16_t send_sz = sz_s;
		buf[0] = 0x81;
		buf[1] = 0x7E;
		buf[2] = sz_s / 256;
		buf[3] = sz_s % 256;
		if (write(fd, buf, 4) != 4) wz_talkers[fd].reset();
		if (write(fd, s, sz_s) != sz_s) wz_talkers[fd].reset();
	}
	else
	{
		log_error("Not implemented: too long answer");
	}
}

bool Websocket_Writer_Impl::write_ping(const char *ws_key, int is_pong)
{
	std::map<std::string, int>::const_iterator fd_it = wz_ws_keys.find(ws_key);
	if (fd_it == wz_ws_keys.end()) return false;

	std::map<int, talker>::const_iterator talker_it = wz_talkers.find(fd_it->second);
	if (talker_it == wz_talkers.end()) return false;
	if (talker_it->second.get_ws_key() != ws_key) return false;

	int fd = fd_it->second;

	char buf[2];
	buf[0] = 0x89;
	buf[1] = 0x00;
	if (is_pong) buf[0]++;
	write(fd, buf, 2);
}

bool Websocket_Writer_Impl::write_close(const char *ws_key, unsigned code)
{
	std::map<std::string, int>::const_iterator fd_it = wz_ws_keys.find(ws_key);
	if (fd_it == wz_ws_keys.end()) return false;

	std::map<int, talker>::const_iterator talker_it = wz_talkers.find(fd_it->second);
	if (talker_it == wz_talkers.end()) return false;
	if (talker_it->second.get_ws_key() != ws_key) return false;

	int fd = fd_it->second;

	char buf[4];
	buf[0] = 0x88;
	buf[1] = 0x02;
	buf[2] = code / 256;
	buf[3] = code % 256;
	write(fd, buf, 4);
}

talker::talker() : fd(-1), cur_header(0), state(R_UNDEFINED), response(0), request(0)
{
	memset(&ip, 0, sizeof(struct in_addr));
	last_access = time(0);
	buffer_cur_read = buffer_cur_write = buffer = 0;
}

void talker::init(int client_fd, const struct in_addr &addr)
{
	if (!buffer) buffer = new char[WZ_BUFFER_SIZE];
	memset(buffer, 0, WZ_BUFFER_SIZE);
	buffer_cur_read = buffer_cur_write = buffer;

	if (!request) request = new Request;
	memset(request, 0, sizeof(Request));
	if (!response) response = new Response;
	memset(response, 0, sizeof(Response));

	request->ip = addr;

	if (!ws_key.empty())
	{
		wz_ws_keys.erase(ws_key);
		plugins.remove_ws_key(ws_key.c_str());
		ws_key.clear();
	}

	fd = client_fd;
	ip = addr;
	state = R_READ_REQUEST_LINE;
	handle();
}

void talker::reset(int dont_close)
{
	if (request->post_body != 0)
	{
		free(request->post_body);
		request->post_body = 0;
		request->content_len = 0;
	}
	if (-1 == fd) return;
	if (dont_close != 1)
	{
#if defined(MODEL_FREEBSD_KQUEUE)
		watchEvent(fd, EVFILT_READ, EV_DELETE, 0, 0);
#elif defined(MODEL_LINUX_EPOLL)
		watchEvent(fd, 0, EPOLL_CTL_DEL);
#else
#error "Unknown model!"
#endif
		if (!ws_key.empty())
		{
//			log_info("socket has key %s, removing link to it", ws_key.c_str());
			global_ws_writer->write_close(ws_key.c_str());
			wz_ws_keys.erase(ws_key);
			plugins.remove_ws_key(ws_key.c_str());
			ws_key.clear();
		}

		close(fd);
		fd = -1;
		memset(&ip, 0, sizeof(struct in_addr));
	}

	memset(request, 0, sizeof(Request));
	memset(response, 0, sizeof(Response));
	memset(buffer, 0, WZ_BUFFER_SIZE);
	buffer_cur_read = buffer_cur_write = buffer;
	request->ip = ip;
	cur_header = 0;
}

void talker::done()
{
	reset();
	if (buffer) delete[] buffer;
	buffer = 0;
}

bool talker::is_timeout(const time_t &t)
{
	if (fd != -1)
	{
//log_info("%d %u %u %u", fd, (unsigned)t, (unsigned)last_access, (unsigned)(t-last_access));
		if (ws_key.empty()) return t - last_access > 30;
		return t - last_access > 300;
	}
	return false;
}

void talker::handle()
{
	if (-1 == fd) return;

	last_access = time(0);
	int in_loop = 1;
	while (in_loop)
	{
		switch (state)
		{
			case R_READ_REQUEST_LINE:
			{
				char *req_line = get_line();
				if (req_line)
				{
					do_request_line(req_line);
				} else in_loop = 0;
				break;
			}
			case R_READ_HEADER:
			{
				char *req_line = get_line();
				if (req_line)
				{
					do_header_line(req_line);
					++cur_header;
				} else in_loop = 0;
				if (state != R_READ_POST_BODY) break;
			}
			case R_READ_POST_BODY:
			{
				if (request->content_len <= 0)
				{
					state = R_HANDLE;
					break;
				}
				if (request->post_body == 0)
				{
					request->post_body = (char*)calloc(request->content_len, 1);
					readed_bytes = 0;
				}
				if (request->post_body != 0)
				{
					int have_to_read_1 = strlen(buffer_cur_read);

					if (have_to_read_1)
					{
						int max_to_read_1 = request->content_len - readed_bytes;
						max_to_read_1 = have_to_read_1 > max_to_read_1 ? max_to_read_1 : have_to_read_1;
						strncpy(request->post_body + readed_bytes, buffer_cur_read, max_to_read_1);
						readed_bytes += max_to_read_1;
						buffer_cur_read += have_to_read_1;
					}

					int max_to_read = request->content_len - readed_bytes;
					int r = read(fd, request->post_body + readed_bytes, max_to_read);
					if (r == -1)
					{
						if (errno != EWOULDBLOCK)
						{
							log_notice("read error for socket %d, closing: %s", fd, strerror(errno));
							reset();
							in_loop = 0;
						}
						else
						{
							in_loop = 0;
						}
					} else {
						readed_bytes += r;
						if (readed_bytes >= request->content_len)
						{
							state = R_HANDLE;
						}
						else
						{
							if (r == 0) in_loop = 0;
						}
					}
				} else state = R_CLOSE;
				break;
			}
			case R_HANDLE:
			{
				do_handle();
				break;
			}
			case R_REPLY:
			{
				do_reply();
				if (state == R_WEBSOCKET)
				{
					reset(1);
				}
				else if (request->keep_alive)
				{
					reset(1);
					state = R_READ_REQUEST_LINE;
				}
				else
				{
					state = R_CLOSE;
				}
				break;
			}
			case R_WEBSOCKET:
			{
				read_websocket();
				in_loop = 0;
				break;
			}
			case R_CLOSE:
			{
				reset();
				in_loop = 0;
				break;
			}
			default:
			{
				log_notice("default action on state %d for %d, closing", state, fd);
				reset();
				in_loop = 0;
			}
		}
	}
}

void talker::read_websocket()
{
	char buf[2048];
	int r;

	do
	{
		r = read(fd, buf, 2048);

		if (r > 0) wspp.parse_buffer(buf, r);
	}
	while (r > 0);

	if (!wspp.is_ok())
	{
		reset();
	}

	websocket_protocol_parser::incoming_events::const_iterator it;
	for (it = wspp.evs.begin(); it != wspp.evs.end(); ++it)
	{
		plugins.handle_websocket_event(ws_key.c_str(), *it);

		if (it->et == ET_PING)
		{
			global_ws_writer->write_ping(ws_key.c_str(), 1);
		}
		else if (it->et == ET_CLOSE)
		{
			reset();
		}
	}

	wspp.evs.clear();
}

char *talker::get_line()
{
	// paranoic, nevertheless we must be sure we have eol in buffer
	buffer_cur_write[0] = 0;
	char *result = 0;
	char *nl = strchr(buffer_cur_read, '\n');
	if (nl)
	{
		result = buffer_cur_read;
		buffer_cur_read = nl + 1;
		nl[0] = 0;
		nl--;
		if (nl[0] == '\r') nl[0] = 0;
	} else {
		int max_to_read = WZ_BUFFER_SIZE - (buffer_cur_write - buffer) - 1;
		if (!max_to_read)
		{
			log_notice("out of buffer memory for fd=%d, ip=%s", fd, inet_ntoa(ip));
			reset();
			return 0;
		}

		int r = read(fd, buffer_cur_write, max_to_read);
		if (r == -1)
		{
			if (errno != EWOULDBLOCK)
			{
				log_notice("read error for socket %d, closing: %s", fd, strerror(errno));
				reset();
			}
		} else {
			if (!r) return 0;
			buffer_cur_write += r;
			return get_line();
		}
	}
	return result;
}

//////////////////////////////////////////////////////////////////////
// Parse system
//////////////////////////////////////////////////////////////////////

void strtolower(char *str)
{
	char *it = str;
	for (; *it; it++) *it = tolower(*it);
}

int parse_request(char *line, Request *r)
{
	char *method;
	char *uri;
	char *uri_params;
	char *proto;
	char *major;
	char *minor;

	method = line;

	if (!(uri = strchr(method, ' '))) return 400;
	*uri++ = 0;
	while ((*uri==' ') && (*uri)) uri++;

	if (!*uri) return 400;

	if (!(proto = strchr(uri, ' '))) return 400;

	*proto++ = 0;
	while ((*proto==' ') && (*proto)) proto++;
	if (!*proto) return 400;

	if (!(major = strchr(proto, '/'))) return 400;
	*major++ = 0;

	if (!(minor = strchr(major, '.'))) return 400;
	*minor++ = 0;

	strtolower(method);
	if (strcmp(method, "get") == 0)
		r->method = Request::REQUEST_GET;
	else if (strcmp(method, "head") == 0)
		r->method = Request::REQUEST_HEAD;
	else if (strcmp(method, "post") == 0)
		r->method = Request::REQUEST_POST;
	else return 501;

	strtolower(proto);
	if (strcmp(proto, "http")) return 400;

	r->major = atol(major);
	if (r->major < 1) r->major = 1;
	r->minor = atol(minor);
	if (r->minor < 0) r->minor = 0;

	if(r->major > 1) return 505;

	uri_params = strchr(uri, '?');
	if (uri_params)
	{
		uri_params[0] = 0;
		uri_params++;
		r->uri_params = uri_params;
	}

	r->uri_path = uri;

	return 0;
}

int parse_header_line(char *line, Request *r, size_t cur_header)
{
	char* value;
	
	value = strchr(line, ':');
	if (!value) return 400;
	value++[0] = 0;
	
	while ((*value==' ') && (*value)) value++;
	if (!*value) return 0;

	strtolower(line);

	if (strlen(value) > 2048) value[2048] = 0;

	if (cur_header < MAX_HEADER_ITEMS)
	{
		r->header_items[cur_header].key = line;
		r->header_items[cur_header].value = value;
	}

	if (!strcmp(line, "cookie"))
	{
		r->cookie = value;
		return 0;
	}

	if (!strcmp(line, "user-agent"))
	{
		strtolower(value);
		r->user_agent = value;
		return 0;
	}

	if (!strncmp(line, "content-len", 10))
	{
		r->content_len = atoi(value);
		return 0;
	}

	if (!strcmp(line, "connection"))
	{
		strtolower(value);
		if (r->minor && !strncmp(value, "keep-alive", 10)) r->keep_alive = 1;
		return 0;
	}

	if (!strcmp(line, "x-forwarded-for"))
	{
		r->x_forwarded_for = value;
		return 0;
	}

	if (!strcmp(line, "referer"))
	{
		r->referer = value;
		return 0;
	}

	if (!strcmp(line, "host"))
	{
		r->host = value;
		return 0;
	}

	if (!strcmp(line, "x-real-ip"))
	{
		r->x_real_ip = value;
		return 0;
	}

	if (!strcmp(line, "upgrade"))
	{
		r->upgrade = value;
		return 0;
	}

	if (!strcmp(line, "connection"))
	{
		r->connection = value;
		return 0;
	}

	if (!strcmp(line, "sec-websocket-key"))
	{
		r->sec_websocket_key = value;
		return 0;
	}

	if (!strcmp(line, "sec-websocket-protocol"))
	{
		r->sec_websocket_protocol = value;
		return 0;
	}

	if (!strcmp(line, "sec-websocket-version"))
	{
		r->sec_websocket_version = value;
		return 0;
	}

	if (!strcmp(line, "sec-websocket-extensions"))
	{
		r->sec_websocket_extensions = value;
		return 0;
	}

	return 0;
}

void talker::do_request_line(char *s)
{
	state = R_READ_HEADER;
	response->status = parse_request(s, request);
	if (response->status)
	{
		std::string &body = response->status < 500 ? cfg->r.error_4xx : cfg->r.error_5xx;
		response->body = body.c_str();
		response->body_len = body.size();
		response->content_type = "text/html";
		state = R_REPLY;
	}
}

void talker::do_header_line(char* s)
{
	if (!s[0])
	{
		if ((request->method == Request::REQUEST_POST) && (request->content_len > 0))
		{
			state = R_READ_POST_BODY;
		}
		else state = R_HANDLE;
		return;
	} else {
		response->status = parse_header_line(s, request, cur_header);
		if (response->status)
		{
			response->body = cfg->r.error_4xx.c_str();
			response->body_len = cfg->r.error_4xx.size();
			response->content_type = "text/html";
			state = R_REPLY;
		}
	}
}

void talker::do_reply()
{
	int l;
	char b[WZ_BUFFER_SIZE];
	char now_str[128];
	time_t now_time;
	time(&now_time);
	memset(now_str, 0, 128);
	strftime(now_str, 127, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&now_time));

	l = snprintf(b, WZ_BUFFER_SIZE, 
		"HTTP/%d.%d %d %s\r\n"
		"Server: muflon/" VERSION "\r\n"
		"Date: %s\r\n",
		request->major, request->minor, response->status,
		cfg->r.http_codes[response->status].c_str(), now_str);


	if (response->upgrade)
		l += snprintf(b + l, WZ_BUFFER_SIZE - l, "Upgrade: %s\r\n", response->upgrade);

	if (response->connection)
		l += snprintf(b + l, WZ_BUFFER_SIZE - l, "Connection: %s\r\n", response->connection);

	if (response->sec_websocket_accept)
		l += snprintf(b + l, WZ_BUFFER_SIZE - l, "Sec-WebSocket-Accept: %s\r\n", response->sec_websocket_accept);

	if (response->content_type)
		l += snprintf(b + l, WZ_BUFFER_SIZE - l, "Content-Type: %s\r\n", response->content_type);

	if (request->keep_alive)
		l += snprintf(b + l, WZ_BUFFER_SIZE - l, "Connection: keep-alive\r\n");
	
	if (response->location)
		l += snprintf(b + l, WZ_BUFFER_SIZE - l, "Location: %s\r\n", response->location);

	if (response->set_cookie || response->set_cookie2)
	{
		l += snprintf(b + l, WZ_BUFFER_SIZE - l, "P3P: policyref=\"/w3c/p3p.xml\", CP=\"NON DSP COR CUR ADM DEV PSA PSD OUR UNR BUS UNI COM NAV INT DEM STA\"\r\n");
		if (response->set_cookie) l += snprintf(b + l, WZ_BUFFER_SIZE - l, "Set-Cookie: %s\r\n", response->set_cookie);
		if (response->set_cookie2) l += snprintf(b + l, WZ_BUFFER_SIZE - l, "Set-Cookie: %s\r\n", response->set_cookie2);
	}

	if (!response->can_cache)
		l += snprintf(b + l, WZ_BUFFER_SIZE - l, "Pragma: no-cache\r\nCache-control: no-cache\r\n");

	if (response->body && response->body_len)
	{
		l += snprintf(b + l, WZ_BUFFER_SIZE - l,
			"Accept-Ranges: bytes\r\n"
			"Content-Length: %d\r\n", response->body_len);
	}

	l += snprintf(b + l, WZ_BUFFER_SIZE - l, "\r\n");
	write(fd, b, l);
	
	if (response->body && response->body_len)
	{
		write(fd, response->body, response->body_len);
	}

	if (!response->ws_key)
	{
		state = R_CLOSE;
	}
	else
	{
		state = R_WEBSOCKET;
	}
}

void talker::do_handle()
{
	if (-1 == fd) return;
	if (response->status) return;

	plugins.handle(request, response);
	
	if (!response->status)
	{
		response->status = 404;
		response->body = cfg->r.default_answer.c_str();
		response->body_len = cfg->r.default_answer.size();
	}

	if (response->ws_key)
	{
		wz_ws_keys[response->ws_key] = fd;
		ws_key = response->ws_key;
	}

	state = R_REPLY;
}


