#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wspp.hpp>

void websocket_protocol_parser::reset()
{
	incoming_event ev;

	if (frame_fin == OP_FIN)
	{
		switch (frame_type)
		{
			case FRAME_STRING:
			case FRAME_BINARY:
			{
				ev.et = (frame_type == FRAME_STRING) ? ET_STRING : ET_BINARY;
				ev.data = _data_col;
//				fprintf(stderr, "FINAL STRING: %s\n", _data_col.c_str());
				break;
			}

			case FRAME_CONTROL_CONCLOSE:
			{
				unsigned xcode = 0;
				if (_data_col.size() == 2)
				{
					xcode = 256 * (unsigned char)_data_col[0];
					xcode += (unsigned char)_data_col[1];
				}
				ev.et = ET_CLOSE;
				ev.code = xcode;
//				fprintf(stderr, "WS CLOSE, code %u\n", xcode);
				break;
			}

			case FRAME_CONTROL_PING:
				ev.et = ET_PING;
				break;

			case FRAME_CONTROL_PONG:
				ev.et = ET_PONG;
				break;

			default:
				fprintf(stderr, "not impl\n");
				break;
		}

		evs.push_back(ev);

		_data_col.clear();
		frame_type = FRAME_UNDEF;
	}

	state = ST_START;
	frame_fin = OP_FUN_UNDEF;
	mask = MASK_UNDEF;
}

void websocket_protocol_parser::parse_buffer(char *buf, size_t sz)
{
//	size_t xpos = 0;
//	while (xpos < sz) fprintf(stderr, "%02X ", (unsigned char)buf[xpos++]);
//	fprintf(stderr, "\n");

	size_t pos = 0;

	while (pos < sz)
	{
		switch (state)
		{
			case ST_START:
			{
				const char X = buf[pos];
				++pos;

				if ((X & 0x70) != 0)
				{
					state = ST_ERROR;
				}
				else
				{
					frame_fin = ((X & 0x80) == 0) ? OP_NOT_FIN : OP_FIN;

					char opcode = X & 0x0F;
					if ((opcode != 0) != (FRAME_UNDEF == frame_type))
					{
						state = ST_ERROR;
					}
					else
					{
						switch (opcode)
						{
							case 0x01:
								frame_type = FRAME_STRING;
								break;
							case 0x02:
								frame_type = FRAME_BINARY;
								break;
							case 0x08:
								frame_type = FRAME_CONTROL_CONCLOSE;
								break;
							case 0x09:
								frame_type = FRAME_CONTROL_PING;
								break;
							case 0x0a:
								frame_type = FRAME_CONTROL_PONG;
								break;
						}
					}
				}

				state = (FRAME_UNDEF != frame_type) ? ST_PAYLOAD : ST_ERROR;

				break;
			}

			case ST_PAYLOAD:
			{
				if (mask == MASK_UNDEF)
				{
					const char X = buf[pos];
					++pos;

					mask = ((X & 0x80) == 0) ? NOMASK : MASK;

					data_sz = 0;
					unsigned char _sz = X & 0x7F;
					if (_sz == 126)
					{
						pl_extra_bytes_processed = 0;
						pl_extra_bytes = 2;
					}
					else if (_sz == 127)
					{
						pl_extra_bytes_processed = 0;
						pl_extra_bytes = 8;
					}
					else
					{
						data_sz = _sz;
						pl_extra_bytes_processed = 0;
						pl_extra_bytes = 0;
					}
				}
				else if (pl_extra_bytes_processed < pl_extra_bytes)
				{
					unsigned char X = buf[pos];
					++pos;
					++pl_extra_bytes_processed;
					data_sz *= 256;
					data_sz += X;
				}
				else
				{
					if (mask == NOMASK)
					{
						state = ST_READ_DATA;
					}
					else
					{
						mask_byte_loaded = 0;
						mask_iterator = 0;
						state = ST_READ_MASK;
					}
				}

				break;
			}

			case ST_READ_MASK:
			{
				if (mask_byte_loaded < 4)
				{
					mask_value[mask_byte_loaded++] = buf[pos++];
				}
				else
				{
					state = ST_READ_DATA;
				}
				break;
			}

			case ST_READ_DATA:
			{
				size_t can_take = sz - pos;
				if (can_take > data_sz) can_take = data_sz;

				if (mask == MASK)
				{
					for (unsigned i = 0; i < can_take; ++i) buf[pos+i] ^= mask_value[(mask_iterator++) % 4];
				}

				_data_col.append(buf + pos, can_take);

				data_sz -= can_take;
				pos += can_take;

				if (0 == data_sz)
				{
					reset();
				}

				break;
			}

			default:
				pos = sz;
				state = ST_ERROR;
				break;
		}
	}
}

