#ifndef __websocket_protocol_parser_UMTNRTBERVRTVRTVETE__
#define __websocket_protocol_parser_UMTNRTBERVRTVRTVETE__

#include <string>
#include <vector>

typedef enum
{
	ET_UNDEF = 0,
	ET_STRING = 1,
	ET_BINARY,
	ET_CLOSE,
	ET_PING,
	ET_PONG
} websocket_protocol_et;

class websocket_protocol_parser
{
	enum { ST_ERROR = -1, ST_START = 0, ST_PAYLOAD, ST_READ_MASK, ST_READ_DATA, ST_READ_COMPLETE } state;
	
	// detect frame type
	enum { OP_FUN_UNDEF = -1, OP_NOT_FIN = 0, OP_FIN = 1 } frame_fin;
	enum { FRAME_UNDEF = 0, FRAME_STRING, FRAME_BINARY, FRAME_CONTROL_CONCLOSE, FRAME_CONTROL_PING, FRAME_CONTROL_PONG } frame_type;

	// detect payload
	enum { MASK_UNDEF = -1, NOMASK = 0, MASK = 1 } mask;
	size_t mask_byte_loaded;
	char mask_value[4];
	size_t mask_iterator;

	size_t pl_extra_bytes;
	size_t pl_extra_bytes_processed;
	size_t data_sz;

	std::string _data_col;

	void reset();
public:
	websocket_protocol_parser()
		: state(ST_START)
		, frame_fin(OP_FUN_UNDEF)
		, frame_type(FRAME_UNDEF)
		, mask(MASK_UNDEF)
		, mask_byte_loaded(0)
		, mask_iterator(0)
		, pl_extra_bytes(0)
		, pl_extra_bytes_processed(0)
		, data_sz(0)
	{
	}

	struct incoming_event
	{
		websocket_protocol_et et;
		std::string data;
		unsigned code;
		incoming_event()
			: et(ET_UNDEF)
			, code(0)
		{
		}
	};

	typedef std::vector<incoming_event> incoming_events;
	incoming_events evs;

	void parse_buffer(char *buf, size_t sz);

	bool is_ok()
	{
		return (state != ST_ERROR);
	}
};

#endif 

