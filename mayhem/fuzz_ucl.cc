/* libucl: parse (UCL / JSON / msgpack / CBOR / csexp auto-detected), then re-emit in every format. */
#include "config.h"
#include "ucl.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2 || size > (1u << 18)) {
		return -1;
	}

	struct ucl_parser *parser = ucl_parser_new(UCL_PARSER_SAFE_FLAGS);
	bool ok = ucl_parser_add_chunk_full(parser, data, size, 0, UCL_DUPLICATE_APPEND, UCL_PARSE_AUTO);

	if (ok) {
		ucl_object_t *obj = ucl_parser_get_object(parser);

		if (obj) {
			for (int fmt = UCL_EMIT_JSON; fmt < UCL_EMIT_MAX; fmt++) {
				size_t len = 0;
				unsigned char *out = ucl_object_emit_len(obj, (enum ucl_emitter) fmt, &len);
				free(out);
			}
			ucl_object_unref(obj);
		}
	}

	ucl_parser_free(parser);

	return ok ? 0 : -1;
}
