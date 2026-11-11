/* HTML parser: tag tree, entities, CSS style handling and URL extraction from attributes. */
#include "fuzz_init.h"
#include "libserver/task.h"
#include "libserver/html/html.hxx"

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
	fuzz_rspamd_init();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2 || size > (1u << 20)) {
		return -1;
	}

	rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "fuzz_html", 0);
	struct rspamd_task task;
	memset(&task, 0, sizeof(task));
	task.task_pool = pool;

	GByteArray *in = g_byte_array_sized_new(size);
	g_byte_array_append(in, data, size);

	khash_t(rspamd_url_hash) *urls = kh_init(rspamd_url_hash);
	GPtrArray *part_urls = g_ptr_array_new();
	std::uint16_t url_order = 0;

	auto *hc = rspamd::html::html_process_input(&task, in, nullptr, urls, part_urls, true, &url_order);
	int ret = 0;

	if (hc == nullptr) {
		ret = -1;
	}
	else {
		(void) rspamd::html::html_debug_structure(*hc);
	}

	g_ptr_array_free(part_urls, TRUE);
	kh_destroy(rspamd_url_hash, urls);
	g_byte_array_free(in, TRUE);
	rspamd_mempool_delete(pool);

	return ret;
}
