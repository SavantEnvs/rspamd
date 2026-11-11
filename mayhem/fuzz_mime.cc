/* Full MIME message parse: headers, multipart tree, text/HTML parts, URLs, images. */
#include "fuzz_init.h"
#include "libserver/task.h"
#include "libmime/message.h"

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

	char *msg = (char *) g_malloc(size);
	memcpy(msg, data, size);

	struct rspamd_task *task = rspamd_task_new(NULL, fuzz_cfg, NULL, NULL, NULL, FALSE);
	task->msg.begin = msg;
	task->msg.len = size;

	int ret = 0;

	if (rspamd_message_parse(task)) {
		rspamd_message_process(task);
	}
	else {
		ret = -1;
	}

	rspamd_task_free(task);
	g_free(msg);

	return ret;
}
