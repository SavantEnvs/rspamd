/* URL discovery in free text and direct URL parsing. */
#include "fuzz_init.h"

static gboolean
url_cb(struct rspamd_url *u, gsize start, gsize end, gpointer ud)
{
	(*(unsigned *) ud)++;
	return TRUE;
}

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
	fuzz_rspamd_init();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 3 || size > (1u << 16)) {
		return -1;
	}

	char *buf = (char *) g_malloc(size);
	memcpy(buf, data, size);

	rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "fuzz_url", 0);
	unsigned found = 0;

	rspamd_url_find_multiple(pool, buf, size, RSPAMD_URL_FIND_ALL, NULL, url_cb, &found, NULL);
	rspamd_url_find_multiple(pool, buf, size, RSPAMD_URL_FIND_STRICT, NULL, url_cb, &found, NULL);

	/* Direct parse of the whole input, with the NUL terminator the API expects */
	char *str = (char *) g_malloc(size + 1);
	memcpy(str, data, size);
	str[size] = '\0';

	struct rspamd_url *url = (struct rspamd_url *) rspamd_mempool_alloc0(pool, sizeof(*url));
	enum uri_errno rc = rspamd_url_parse(url, str, size, pool, RSPAMD_URL_PARSE_TEXT, NULL);

	rspamd_mempool_delete(pool);
	g_free(str);
	g_free(buf);

	return (found == 0 && rc != URI_ERRNO_OK) ? -1 : 0;
}
